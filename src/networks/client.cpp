#include <iostream>
#include <limits>
#include <random>
#include <thread>
#include "client.hpp"
#include "../shares/data_operations.hpp"

using namespace std::placeholders;
using namespace std::chrono;
using namespace std::literals;


client_mode::~client_mode()
{
	timer_find_timeout.cancel();
	timer_expiring_sessions.cancel();
	timer_keep_alive.cancel();
}

bool client_mode::start()
{
	printf("start_up() running in client mode (UDP)\n");

	uint16_t port_number = current_settings.listen_port;
	if (port_number == 0)
		return false;

	udp::endpoint listen_on_ep;
	if (current_settings.ipv4_only)
		listen_on_ep = udp::endpoint(udp::v4(), port_number);
	else
		listen_on_ep = udp::endpoint(udp::v6(), port_number);

	if (!current_settings.listen_on.empty())
	{
		asio::error_code ec;
		asio::ip::address local_address = asio::ip::make_address(current_settings.listen_on, ec);
		if (ec)
		{
			std::string error_message = time_to_string_with_square_brackets() + current_settings.listen_on + "\n";
			std::cerr << error_message;
			print_message_to_file(error_message, current_settings.log_messages);
			return false;
		}

		if (local_address.is_v4() && !current_settings.ipv4_only)
			listen_on_ep.address(asio::ip::make_address_v6(asio::ip::v4_mapped, local_address.to_v4()));
		else
			listen_on_ep.address(local_address);
	}


	try
	{
		udp_callback_t udp_func_ap = std::bind(&client_mode::udp_listener_incoming, this, _1, _2, _3, _4);
		udp_access_point = std::make_unique<udp_server>(network_io, sequence_task_pool_local, task_limit, listen_on_ep, udp_func_ap);

		timer_find_timeout.expires_after(FINDER_TIMEOUT_INTERVAL);
		timer_find_timeout.async_wait([this](const asio::error_code &e) { find_expires(e); });

		timer_expiring_sessions.expires_after(EXPRING_UPDATE_INTERVAL);
		timer_expiring_sessions.async_wait([this](const asio::error_code &e) { expiring_wrapper_loops(e); });

		if (current_settings.keep_alive > 0)
		{
			timer_keep_alive.expires_after(seconds{ current_settings.keep_alive });
			timer_keep_alive.async_wait([this](const asio::error_code &e) { keep_alive(e); });
		}
	}
	catch (std::exception &ex)
	{
		std::string error_message = time_to_string_with_square_brackets() + ex.what();
		std::cerr << error_message << std::endl;
		print_message_to_file(error_message + "\n", current_settings.log_messages);
		return false;
	}

	return true;
}

void client_mode::udp_listener_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type port_number)
{
	if (data_size == 0)
		return;

	std::shared_ptr<udp_mappings> udp_session = nullptr;

	{
		std::shared_lock share_locker_udp_session_map_to_wrapper{ mutex_udp_endpoint_map_to_session, std::defer_lock };
		std::unique_lock unique_locker_udp_session_map_to_wrapper{ mutex_udp_endpoint_map_to_session, std::defer_lock };
		share_locker_udp_session_map_to_wrapper.lock();

		auto iter = udp_endpoint_map_to_session.find(peer);
		if (iter == udp_endpoint_map_to_session.end())
		{
			share_locker_udp_session_map_to_wrapper.unlock();
			unique_locker_udp_session_map_to_wrapper.lock();
			iter = udp_endpoint_map_to_session.find(peer);
			if (iter == udp_endpoint_map_to_session.end())
			{
				const std::string& destination_address = current_settings.destination_address;
				uint16_t destination_port = current_settings.destination_port;
				if (destination_port == 0)
					destination_port = generate_new_port_number(current_settings.destination_port_start, current_settings.destination_port_end);

				uint32_t key_number = generate_token_number();

				std::shared_ptr<udp_mappings> udp_session_ptr = std::make_shared<udp_mappings>();
				auto udp_func = std::bind(&client_mode::udp_connector_incoming_to_udp, this, _1, _2, _3, _4, _5);
				std::shared_ptr<forwarder> udp_forwarder = std::make_shared<forwarder>(io_context, sequence_task_pool_peer, task_limit, udp_session_ptr, udp_func, current_settings.ipv4_only);
				if (udp_forwarder == nullptr)
					return;

				bool success = get_udp_target(udp_forwarder, udp_session_ptr->egress_target_endpoint);
				if (!success)
					return;

				std::shared_ptr<packet::data_wrapper> data_wrapper_ptr = std::make_shared<packet::data_wrapper>(key_number, udp_session_ptr);
				udp_session_ptr->wrapper_ptr = data_wrapper_ptr;
				udp_session_ptr->changeport_timestamp.store(right_now() + current_settings.dynamic_port_refresh);
				udp_session_ptr->egress_forwarder = udp_forwarder;
				udp_session_ptr->egress_previous_target_endpoint = udp_session_ptr->egress_target_endpoint;
				udp_session_ptr->ingress_source_endpoint = peer;

				uint8_t *packing_data_ptr = data.get();
				size_t packed_data_size = data_wrapper_ptr->pack_data(packing_data_ptr, data_size);
				auto [error_message, cipher_size] = encrypt_data(current_settings.encryption_password, current_settings.encryption, packing_data_ptr, (int)packed_data_size);
				if (!error_message.empty() || cipher_size == 0)
					return;

				asio::error_code ec;
				udp_forwarder->send_out(packing_data_ptr, cipher_size, udp_session_ptr->egress_target_endpoint, ec);
				if (ec)
				{
					std::string error_message = time_to_string_with_square_brackets() + "Cannot Send Data: " + ec.message();
					std::cerr << error_message << "\n";
					print_message_to_file(error_message + "\n", current_settings.log_messages);
					return;
				}
				udp_forwarder->async_receive();

				std::scoped_lock locker{ mutex_udp_session_channels };
				udp_session_channels[key_number] = udp_session_ptr;
				udp_endpoint_map_to_session[peer] = udp_session_ptr;

				return;
			}
			else
			{
				udp_session = iter->second;
			}
		}
		else
		{
			udp_session = iter->second;
		}
	}

	uint8_t *packing_data_ptr = data.get();
	auto packed_data_size = udp_session->wrapper_ptr->pack_data(packing_data_ptr, data_size);

	auto [error_message, cipher_size] = encrypt_data(current_settings.encryption_password, current_settings.encryption, packing_data_ptr, (int)packed_data_size);
	if (error_message.empty() && cipher_size > 0)
		udp_session->egress_forwarder->async_send_out(std::move(data), packing_data_ptr, cipher_size, udp_session->egress_target_endpoint);
	change_new_port(udp_session);
}


void client_mode::udp_connector_incoming_to_udp(std::weak_ptr<udp_mappings> udp_session_weak_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type local_port_number)
{
	std::shared_ptr<udp_mappings> udp_session_ptr = udp_session_weak_ptr.lock();
	if (data_size == 0 || udp_session_ptr == nullptr)
		return;

	if (data_size < RAW_HEADER_SIZE)
		return;

	uint8_t *data_ptr = data.get();
	auto [error_message, plain_size] = decrypt_data(current_settings.encryption_password, current_settings.encryption, data_ptr, (int)data_size);
	if (!error_message.empty() || plain_size == 0)
		return;

	udp_connector_incoming_to_udp_unpack(udp_session_ptr, std::move(data), plain_size, peer, local_port_number);
}

void client_mode::udp_connector_incoming_to_udp_unpack(std::shared_ptr<udp_mappings> udp_session_ptr, std::unique_ptr<uint8_t[]> data, size_t plain_size, udp::endpoint peer, asio::ip::port_type local_port_number)
{
	if (plain_size == 0 || udp_session_ptr == nullptr)
		return;

	uint8_t *data_ptr = data.get();

	uint32_t iden = udp_session_ptr->wrapper_ptr->extract_iden(data_ptr);
	if (udp_session_ptr->wrapper_ptr->get_iden() != iden)
	{
		return;
	}

	auto [packet_timestamp, received_data_ptr, received_size] = udp_session_ptr->wrapper_ptr->receive_data(data_ptr, plain_size);
	if (received_size == 0)
		return;

	if (packet_timestamp != 0)
	{
		auto timestamp = right_now();
		if (calculate_difference(timestamp, packet_timestamp) > TIME_GAP)
			return;

		std::shared_lock shared_locker_ingress_endpoint{ udp_session_ptr->mutex_ingress_endpoint };
		udp::endpoint udp_endpoint = udp_session_ptr->ingress_source_endpoint;
		shared_locker_ingress_endpoint.unlock();

		udp_access_point->async_send_out(std::move(data), received_data_ptr, received_size, udp_endpoint);
	}

	std::shared_lock shared_lock_udp_target{ udp_session_ptr->mutex_egress_endpoint };
	if (udp_session_ptr->egress_target_endpoint != peer && udp_session_ptr->egress_previous_target_endpoint != peer)
	{
		shared_lock_udp_target.unlock();
		std::scoped_lock unique_lock_udp_target{ udp_session_ptr->mutex_egress_endpoint, mutex_target_address };
		if (udp_session_ptr->egress_target_endpoint != peer)
		{
			udp_session_ptr->egress_previous_target_endpoint = udp_session_ptr->egress_target_endpoint;
			udp_session_ptr->egress_target_endpoint = peer;
			*target_address = peer.address();
		}
	}
}

bool client_mode::get_udp_target(std::shared_ptr<forwarder> target_connector, udp::endpoint &udp_target)
{
	if (target_address != nullptr)
	{
		uint16_t destination_port = current_settings.destination_port;
		if (destination_port == 0)
			destination_port = generate_new_port_number(current_settings.destination_port_start, current_settings.destination_port_end);

		udp_target = udp::endpoint(*target_address, destination_port);
		return true;
	}

	return update_udp_target(target_connector, udp_target);
}

bool client_mode::update_udp_target(std::shared_ptr<forwarder> target_connector, udp::endpoint &udp_target)
{
	uint16_t destination_port = current_settings.destination_port;
	if (destination_port == 0)
		destination_port = generate_new_port_number(current_settings.destination_port_start, current_settings.destination_port_end);

	bool connect_success = false;
	asio::error_code ec;
	for (int i = 0; i <= RETRY_TIMES; ++i)
	{
		const std::string &destination_address = current_settings.destination_address;
		udp::resolver::results_type udp_endpoints = target_connector->get_remote_hostname(destination_address, destination_port, ec);
		if (ec)
		{
			std::string error_message = time_to_string_with_square_brackets() + ec.message() + "\n";
			std::cerr << error_message;
			print_message_to_file(error_message, current_settings.log_messages);
			std::this_thread::sleep_for(std::chrono::seconds(RETRY_WAITS));
		}
		else if (udp_endpoints.size() == 0)
		{
			std::string error_message = time_to_string_with_square_brackets() + "destination address not found\n";
			std::cerr << error_message;
			print_message_to_file(error_message, current_settings.log_messages);
			std::this_thread::sleep_for(std::chrono::seconds(RETRY_WAITS));
		}
		else
		{
			std::scoped_lock locker{ mutex_target_address };
			udp_target = *udp_endpoints.begin();
			target_address = std::make_unique<asio::ip::address>(udp_target.address());
			connect_success = true;
			break;
		}
	}

	return connect_success;
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
		std::shared_ptr<forwarder> forwarder_ptr = iter->first;
		int64_t expire_time= iter->second;

		int64_t time_elapsed = calculate_difference(time_right_now, expire_time);

		if (time_elapsed <= CLEANUP_WAITS / 2)
			continue;

		if (time_elapsed > CLEANUP_WAITS / 2 && time_elapsed < CLEANUP_WAITS)
		{
			forwarder_ptr->remove_callback();
			forwarder_ptr->stop();
			continue;
		}

		forwarder_ptr->disconnect();
		expiring_forwarders.erase(iter);
	}
}

void client_mode::cleanup_expiring_data_connections()
{
	auto time_right_now = right_now();

	std::scoped_lock lockers{ mutex_expiring_sessions, mutex_udp_endpoint_map_to_session };
	for (auto iter = expiring_sessions.begin(), next_iter = iter; iter != expiring_sessions.end(); iter = next_iter)
	{
		++next_iter;
		auto &[udp_session_ptr, expire_time] = *iter;
		uint32_t iden = udp_session_ptr->wrapper_ptr->get_iden();

		if (calculate_difference(time_right_now, expire_time) < CLEANUP_WAITS)
			continue;

		udp_endpoint_map_to_session.erase(udp_session_ptr->ingress_source_endpoint);
		expiring_sessions.erase(iter);
	}
}

void client_mode::loop_timeout_sessions()
{
	std::scoped_lock lockers{ mutex_udp_session_channels, mutex_expiring_sessions };
	for (auto iter = udp_session_channels.begin(), next_iter = iter; iter != udp_session_channels.end(); iter = next_iter)
	{
		++next_iter;
		uint32_t iden = iter->first;
		std::shared_ptr<udp_mappings> udp_session_ptr = iter->second;

		if (udp_session_ptr->egress_forwarder->time_gap_of_receive() > current_settings.timeout &&
			udp_session_ptr->egress_forwarder->time_gap_of_send() > current_settings.timeout)
		{
			if (expiring_sessions.find(udp_session_ptr) == expiring_sessions.end())
				expiring_sessions[udp_session_ptr] = right_now();

			udp_session_channels.erase(iter);
			udp_session_ptr->changeport_timestamp.store(LLONG_MAX);
		}
	}
}

void client_mode::loop_keep_alive()
{
	std::shared_lock locker{ mutex_udp_session_channels };
	for (auto &[iden, udp_session_ptr] : udp_session_channels)
	{
		if (udp_session_ptr->changeport_timestamp.load() > right_now())
		{
			std::vector<uint8_t> keep_alive_packet = create_empty_data(current_settings.encryption_password, current_settings.encryption, EMPTY_PACKET_SIZE);
			udp_session_ptr->wrapper_ptr->write_iden(keep_alive_packet.data());
			udp_session_ptr->egress_forwarder->async_send_out(std::move(keep_alive_packet), udp_session_ptr->egress_target_endpoint);
		}
	}
}

void client_mode::find_expires(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
		return;

	loop_timeout_sessions();

	timer_find_timeout.expires_after(FINDER_TIMEOUT_INTERVAL);
	timer_find_timeout.async_wait([this](const asio::error_code &e) { find_expires(e); });
}

void client_mode::expiring_wrapper_loops(const asio::error_code & e)
{
	if (e == asio::error::operation_aborted)
		return;

	cleanup_expiring_forwarders();
	cleanup_expiring_data_connections();

	timer_expiring_sessions.expires_after(EXPRING_UPDATE_INTERVAL);
	timer_expiring_sessions.async_wait([this](const asio::error_code &e) { expiring_wrapper_loops(e); });
}

void client_mode::change_new_port(std::shared_ptr<udp_mappings> udp_mappings_ptr)
{
	if (udp_mappings_ptr->changeport_timestamp.load() > right_now())
		return;
	udp_mappings_ptr->changeport_timestamp += current_settings.dynamic_port_refresh;

	uint32_t iden = udp_mappings_ptr->wrapper_ptr->get_iden();
	asio::error_code ec;

	auto udp_func = std::bind(&client_mode::udp_connector_incoming_to_udp, this, _1, _2, _3, _4, _5);
	auto udp_forwarder = std::make_shared<forwarder>(io_context, sequence_task_pool_peer, task_limit, udp_mappings_ptr, udp_func, current_settings.ipv4_only);
	if (udp_forwarder == nullptr)
		return;

	uint16_t destination_port_start = current_settings.destination_port_start;
	uint16_t destination_port_end = current_settings.destination_port_end;
	if (destination_port_start != destination_port_end)
	{
		uint16_t new_port_numer = generate_new_port_number(destination_port_start, destination_port_end);
		std::shared_lock locker{ mutex_target_address };
		asio::ip::address temp_address = *target_address;
		locker.unlock();
		std::scoped_lock locker_egress{ udp_mappings_ptr->mutex_egress_endpoint };
		udp_mappings_ptr->egress_target_endpoint.address(temp_address);
		udp_mappings_ptr->egress_target_endpoint.port(new_port_numer);
	}

	std::shared_ptr<forwarder> new_forwarder = udp_forwarder;
	std::vector<uint8_t> keep_alive_packet = create_empty_data(current_settings.encryption_password, current_settings.encryption, EMPTY_PACKET_SIZE);
	udp_mappings_ptr->wrapper_ptr->write_iden(keep_alive_packet.data());

	if (current_settings.ipv4_only)
		new_forwarder->send_out(std::move(keep_alive_packet), local_empty_target_v4, ec);
	else
		new_forwarder->send_out(std::move(keep_alive_packet), local_empty_target_v6, ec);

	if (ec)
		return;

	new_forwarder->async_receive();

	std::shared_ptr<forwarder> old_forwarder = udp_mappings_ptr->egress_forwarder;
	udp_mappings_ptr->egress_forwarder = new_forwarder;

	std::scoped_lock lock_expiring_forwarders{ mutex_expiring_forwarders };
	expiring_forwarders.insert({ old_forwarder, right_now() });
}

void client_mode::keep_alive(const asio::error_code& e)
{
	if (e == asio::error::operation_aborted)
		return;

	loop_keep_alive();

	timer_keep_alive.expires_after(seconds{ current_settings.keep_alive });
	timer_keep_alive.async_wait([this](const asio::error_code &e) { keep_alive(e); });
}