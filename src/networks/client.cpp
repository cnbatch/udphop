#include <iostream>
#include <limits>
#include <random>
#include <thread>
#include "client.hpp"

using namespace std::placeholders;
using namespace std::chrono;
using namespace std::literals;


client_mode::~client_mode()
{
	timer_find_timeout.cancel();
	timer_change_ports.cancel();
}

bool client_mode::start()
{
	printf("start_up() running in client mode (UDP)\n");

	uint16_t port_number = current_settings.listen_port;
	if (port_number == 0)
		return false;

	udp::endpoint listen_on_ep(udp::v6(), port_number);
	if (!current_settings.listen_on.empty())
	{
		asio::error_code ec;
		asio::ip::address local_address = asio::ip::make_address(current_settings.listen_on, ec);
		if (ec)
		{
			std::cerr << "Listen Address incorrect - " << current_settings.listen_on << "\n";
			if (!current_settings.log_messages.empty())
				print_message_to_file("Listen Address incorrect - " + current_settings.listen_on + "\n", current_settings.log_messages);
			return false;
		}

		if (local_address.is_v4())
			listen_on_ep.address(asio::ip::make_address_v6(asio::ip::v4_mapped, local_address.to_v4()));
		else
			listen_on_ep.address(local_address);
	}


	try
	{
		udp_callback_t udp_func_ap = std::bind(&client_mode::udp_server_incoming, this, _1, _2, _3, _4);
		udp_access_point = std::make_unique<udp_server>(network_io, asio_strand, listen_on_ep, udp_func_ap);

		timer_find_timeout.expires_after(EXPRING_UPDATE_INTERVAL);
		timer_find_timeout.async_wait([this](const asio::error_code &e) { wrapper_loop_updates(e); });

		timer_change_ports.expires_after(CHANGEPORT_UPDATE_INTERVAL);
		timer_change_ports.async_wait([this](const asio::error_code &e) { change_new_port(e); });
	}
	catch (std::exception &ex)
	{
		std::cerr << ex.what() << std::endl;
		return false;
	}

	return true;
}

void client_mode::udp_server_incoming(std::shared_ptr<uint8_t[]> data, size_t data_size, udp::endpoint &&peer, asio::ip::port_type port_number)
{
	if (data_size == 0)
		return;

	std::shared_lock share_locker_udp_session_map_to_wrapper{ mutex_udp_session_map_to_wrapper, std::defer_lock };
	std::unique_lock unique_locker_udp_session_map_to_wrapper{ mutex_udp_session_map_to_wrapper, std::defer_lock };
	share_locker_udp_session_map_to_wrapper.lock();

	auto iter = udp_session_map_to_wrapper.find(peer);
	if (iter == udp_session_map_to_wrapper.end())
	{
		share_locker_udp_session_map_to_wrapper.unlock();
		unique_locker_udp_session_map_to_wrapper.lock();
		iter = udp_session_map_to_wrapper.find(peer);
		if (iter == udp_session_map_to_wrapper.end())
		{
			const std::string &destination_address = current_settings.destination_address;
			uint16_t destination_port = current_settings.destination_port;
			if (destination_port == 0)
				destination_port = generate_new_port_number(current_settings.destination_port_start, current_settings.destination_port_end);

			uint32_t key_number = generate_token_number();

			std::unique_ptr<data_wrapper<forwarder>> data_ptr = std::make_unique<data_wrapper<forwarder>>(key_number);
			auto udp_func = std::bind(&client_mode::udp_client_incoming_to_udp, this, _1, _2, _3, _4, _5);
			auto udp_forwarder = std::make_unique<forwarder>(network_io, asio_strand, data_ptr.get(), udp_func);
			if (udp_forwarder == nullptr)
				return;

			asio::error_code ec;
			udp::endpoint endpoint_target;
			for (int i = 0; i < RETRY_TIMES; ++i)
			{
				udp::resolver::results_type udp_endpoints = udp_forwarder->get_remote_hostname(destination_address, destination_port, ec);
				if (ec)
				{
					std::cerr << ec.message() << "\n";
					std::this_thread::sleep_for(std::chrono::seconds(RETRY_WAITS));
				}
				else if (udp_endpoints.size() == 0)
				{
					std::cerr << "destination address not found\n";
					if (!current_settings.log_messages.empty())
						print_message_to_file("destination address not found\n", current_settings.log_messages);
					std::this_thread::sleep_for(std::chrono::seconds(RETRY_WAITS));
				}
				else
				{
					endpoint_target = *udp_endpoints.begin();
					std::scoped_lock locker{ mutex_udp_target };
					udp_target = std::make_unique<udp::endpoint>(endpoint_target);
					previous_udp_target = std::make_unique<udp::endpoint>(endpoint_target);
					break;
				}
			}

			if (ec)
				return;

			uint8_t *packing_data_ptr = data.get();
			size_t packed_data_size = data_ptr->pack_data(packing_data_ptr, data_size);
			auto [error_message, cipher_size] = encrypt_data(current_settings.encryption_password, current_settings.encryption, packing_data_ptr, (int)packed_data_size);
			if (!error_message.empty() || cipher_size == 0)
				return;
			udp_forwarder->send_out(packing_data_ptr, cipher_size, endpoint_target, ec);
			if (ec)
				return;
			udp_forwarder->async_receive();

			data_ptr->forwarder_ptr.store(udp_forwarder.get());

			std::unique_lock lock_wrapper_changeport_timestamp{ mutex_wrapper_changeport_timestamp };
			wrapper_changeport_timestamp[data_ptr.get()].store(right_now() + current_settings.dynamic_port_refresh);
			lock_wrapper_changeport_timestamp.unlock();

			udp_session_map_to_wrapper.insert({ peer, data_ptr.get() });
			wrapper_session_map_to_udp[key_number] = peer;
			id_map_to_forwarder.insert({ key_number, std::move(udp_forwarder) });
			wrapper_channels.insert({ key_number, std::move(data_ptr) });

			return;
		}
		unique_locker_udp_session_map_to_wrapper.unlock();
		share_locker_udp_session_map_to_wrapper.lock();
	}

	data_wrapper<forwarder> *wrapper_session = iter->second;
	share_locker_udp_session_map_to_wrapper.unlock();

	uint8_t *packing_data_ptr = data.get();
	auto packed_data_size = wrapper_session->pack_data(packing_data_ptr, data_size);

	auto [error_message, cipher_size] = encrypt_data(current_settings.encryption_password, current_settings.encryption, packing_data_ptr, (int)packed_data_size);
	if (error_message.empty() && cipher_size > 0)
		wrapper_session->send_data(data, packing_data_ptr, cipher_size, get_remote_address());
}


void client_mode::udp_client_incoming_to_udp(data_wrapper<forwarder> *wrapper, std::shared_ptr<uint8_t[]> data, size_t data_size, udp::endpoint &&peer, asio::ip::port_type local_port_number)
{
	if (data_size == 0 || wrapper == nullptr)
		return;

	uint8_t *data_ptr = data.get();
	auto [error_message, plain_size] = decrypt_data(current_settings.encryption_password, current_settings.encryption, data_ptr, (int)data_size);
	if (!error_message.empty() || plain_size == 0)
		return;

	uint32_t iden = data_wrapper<forwarder>::extract_iden(data_ptr);
	if (wrapper->get_iden() != iden)
	{
		return;
	}

	auto [packet_timestamp, received_data_ptr, received_size] = wrapper->receive_data(data_ptr, plain_size);
	if (received_size == 0)
		return;

	auto timestamp = right_now();
	if (calculate_difference(timestamp, packet_timestamp) > TIME_GAP)
		return;

	std::shared_lock lock_wrapper_session_map_to_udp{ mutex_wrapper_session_map_to_udp };
	auto session_iter = wrapper_session_map_to_udp.find(iden);
	if (session_iter == wrapper_session_map_to_udp.end())
		return;
	udp::endpoint &udp_endpoint = session_iter->second;
	lock_wrapper_session_map_to_udp.unlock();

	udp_access_point->async_send_out(data, received_data_ptr, received_size, udp_endpoint);

	std::shared_lock shared_lock_udp_target{ mutex_udp_target };
	if (*udp_target != peer && *previous_udp_target != peer)
	{
		shared_lock_udp_target.unlock();
		std::unique_lock unique_lock_udp_target{ mutex_udp_target };
		if (*udp_target != peer)
		{
			*previous_udp_target = *udp_target;
			*udp_target = peer;
		}
	}
}

udp::endpoint client_mode::get_remote_address()
{
	udp::endpoint ep;
	std::shared_lock locker{ mutex_udp_target };
	ep = *udp_target;
	locker.unlock();
	return ep;
}

uint16_t client_mode::generate_new_port_number(uint16_t start_port_num, uint16_t end_port_num)
{
	std::random_device rd;
	std::mt19937 mt(rd());
	std::uniform_int_distribution<uint16_t> uniform_dist(start_port_num, end_port_num);
	return uniform_dist(mt);
}

uint32_t client_mode::generate_token_number()
{
	std::random_device rd;
	std::mt19937 mt(rd());
	std::uniform_int_distribution<uint32_t> uniform_dist(32, std::numeric_limits<uint32_t>::max() - 1);
	return uniform_dist(mt);
}


void client_mode::cleanup_expiring_forwarders()
{
	auto time_right_now = right_now();

	std::scoped_lock lockers{ mutex_expiring_forwarders };
	for (auto iter = expiring_forwarders.begin(), next_iter = iter; iter != expiring_forwarders.end(); iter = next_iter)
	{
		++next_iter;
		auto &[udp_forwrder, expire_time] = iter->second;
		forwarder *forwarder_ptr = udp_forwrder.get();

		int64_t time_elapsed = calculate_difference(time_right_now, expire_time);

		if (time_elapsed <= CLEANUP_WAITS / 2)
			continue;

		if (time_elapsed > CLEANUP_WAITS / 2 && time_elapsed < CLEANUP_WAITS)
		{
			forwarder_ptr->remove_callback();
			forwarder_ptr->stop();
			continue;
		}

		expiring_forwarders.erase(iter);
	}
}

void client_mode::cleanup_expiring_data_connections()
{
	auto time_right_now = right_now();

	std::scoped_lock locker{ mutex_expiring_wrapper };
	for (auto iter = expiring_wrapper.begin(), next_iter = iter; iter != expiring_wrapper.end(); iter = next_iter)
	{
		++next_iter;
		uint32_t iden = iter->first;
		auto &[wrapper_ptr, expire_time] = iter->second;

		if (calculate_difference(time_right_now, expire_time) < CLEANUP_WAITS)
			continue;

		std::scoped_lock lockers{ mutex_udp_session_map_to_wrapper, mutex_wrapper_session_map_to_udp,
								  mutex_expiring_forwarders, mutex_wrapper_changeport_timestamp,
								  mutex_wrapper_channels, mutex_id_map_to_forwarder };

		if (auto forwarder_iter = id_map_to_forwarder.find(iden);
			forwarder_iter != id_map_to_forwarder.end())
		{
			std::unique_ptr<forwarder> forwarder_ptr_owner = std::move(forwarder_iter->second);
			forwarder *forwarder_ptr = forwarder_ptr_owner.get();
			forwarder_ptr->remove_callback();
			forwarder_ptr->stop();
			if (expiring_forwarders.find(forwarder_ptr) == expiring_forwarders.end())
				expiring_forwarders.insert({ forwarder_ptr, std::pair{std::move(forwarder_ptr_owner), right_now()} });
			id_map_to_forwarder.erase(forwarder_iter);
		}

		udp::endpoint &udp_endpoint = wrapper_session_map_to_udp[iden];
		udp_session_map_to_wrapper.erase(udp_endpoint);
		wrapper_session_map_to_udp.erase(iden);
		wrapper_changeport_timestamp.erase(wrapper_ptr.get());
		expiring_wrapper.erase(iter);
	}
}

void client_mode::loop_timeout_sessions()
{
	std::scoped_lock lockers{ mutex_wrapper_channels };
	for (auto iter = wrapper_channels.begin(), next_iter = iter; iter != wrapper_channels.end(); iter = next_iter)
	{
		++next_iter;
		uint32_t iden = iter->first;
		data_wrapper<forwarder> *data_ptr = iter->second.get();

		std::unique_lock locker_id_map_to_forwarder{ mutex_id_map_to_forwarder };
		forwarder *udp_forwarder = id_map_to_forwarder.find(iden)->second.get();
		locker_id_map_to_forwarder.unlock();

		if (udp_forwarder->time_gap_of_receive() > TIMEOUT && udp_forwarder->time_gap_of_send() > TIMEOUT)
		{
			std::scoped_lock locker_expiring_wrapper{ mutex_expiring_wrapper };
			if (expiring_wrapper.find(iden) == expiring_wrapper.end())
				expiring_wrapper.insert({ iden, std::pair{ std::move(iter->second), right_now() } });

			wrapper_channels.erase(iter);
			std::scoped_lock locker_wrapper_changeport_timestamp{ mutex_wrapper_changeport_timestamp };
			wrapper_changeport_timestamp.erase(data_ptr);
		}
	}
}

void client_mode::loop_change_new_port()
{
	std::shared_lock locker{ mutex_wrapper_changeport_timestamp };
	for (auto &[wrapper_ptr, timestamp] : wrapper_changeport_timestamp)
	{
		if (timestamp.load() > right_now())
			continue;
		timestamp += current_settings.dynamic_port_refresh;

		uint32_t iden = wrapper_ptr->get_iden();
		asio::error_code ec;

		auto udp_func = std::bind(&client_mode::udp_client_incoming_to_udp, this, _1, _2, _3, _4, _5);
		auto udp_forwarder = std::make_unique<forwarder>(network_io, asio_strand, wrapper_ptr, udp_func);
		if (udp_forwarder == nullptr)
			continue;

		if (current_settings.destination_port_start != current_settings.destination_port_end)
		{
			uint16_t new_port_numer = generate_new_port_number(current_settings.destination_port_start, current_settings.destination_port_end);
			std::scoped_lock locker{ mutex_udp_target };
			*previous_udp_target = *udp_target;
			*udp_target = udp::endpoint(udp_target->address(), new_port_numer);
		}
		
		forwarder *new_forwarder_ptr = udp_forwarder.get();
		new_forwarder_ptr->send_out(create_raw_random_data(EMPTY_PACKET_SIZE), local_empty_target, ec);
		if (ec)
		{
			timestamp += current_settings.dynamic_port_refresh;
			return;
		}
		new_forwarder_ptr->async_receive();

		std::unique_lock locker_id_map_to_forwarder{ mutex_id_map_to_forwarder };
		auto iter_forwarder = id_map_to_forwarder.find(iden);
		if (iter_forwarder == id_map_to_forwarder.end())
			continue;

		std::swap(udp_forwarder, iter_forwarder->second);
		locker_id_map_to_forwarder.unlock();
		wrapper_ptr->forwarder_ptr.store(new_forwarder_ptr);
		forwarder *old_forwarder_ptr = iter_forwarder->second.get();

		std::scoped_lock lock_expiring_forwarders{ mutex_expiring_forwarders };
		expiring_forwarders.insert({ old_forwarder_ptr, std::pair{std::move(udp_forwarder), right_now()} });
	}
}

void client_mode::wrapper_loop_updates(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
		return;

	loop_timeout_sessions();

	timer_find_timeout.expires_after(FINDER_TIMEOUT_INTERVAL);
	timer_find_timeout.async_wait([this](const asio::error_code &e) { wrapper_loop_updates(e); });
}

void client_mode::expiring_wrapper_loops(const asio::error_code & e)
{
	if (e == asio::error::operation_aborted)
		return;

	cleanup_expiring_forwarders();
	cleanup_expiring_data_connections();

	timer_find_timeout.expires_after(EXPRING_UPDATE_INTERVAL);
	timer_find_timeout.async_wait([this](const asio::error_code &e) { expiring_wrapper_loops(e); });
}

void client_mode::change_new_port(const asio::error_code & e)
{
	if (e == asio::error::operation_aborted)
		return;

	loop_change_new_port();

	timer_change_ports.expires_after(1s);
	timer_change_ports.async_wait([this](const asio::error_code &e) { change_new_port(e); });
}

