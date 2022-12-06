#include <algorithm>
#include <iostream>
#include <random>
#include <thread>
#include "server.hpp"

using namespace std::placeholders;
using namespace std::chrono;
using namespace std::literals;


void server_mode::cleanup_expiring_data_connections()
{
	auto time_right_now = right_now();

	std::scoped_lock locker_expiring_wrapper{ mutex_expiring_wrapper };
	for (auto iter = expiring_wrapper.begin(), next_iter = iter; iter != expiring_wrapper.end(); iter = next_iter)
	{
		++next_iter;
		std::shared_ptr<data_wrapper<udp_server>> wrapper_ptr = iter->first;
		int64_t expire_time = iter->second;
		uint32_t iden = wrapper_ptr->get_iden();
		if (calculate_difference(time_right_now, expire_time) < CLEANUP_WAITS)
			continue;

		std::unique_lock locker_wrapper_channels{ mutex_wrapper_channels };
		wrapper_channels.erase(iden);
		locker_wrapper_channels.unlock();

		std::unique_lock locker_wrapper_session_map_to_source_udp{ mutex_wrapper_session_map_to_source_udp };
		wrapper_session_map_to_source_udp.erase(wrapper_ptr);
		locker_wrapper_session_map_to_source_udp.unlock();

		expiring_wrapper.erase(iter);
	}
}

void server_mode::loop_timeout_sessions()
{
	std::scoped_lock locker_wrapper_looping{ mutex_wrapper_channels };
	for (auto iter = wrapper_channels.begin(), next_iter = iter; iter != wrapper_channels.end(); iter = next_iter)
	{
		++next_iter;
		uint32_t iden = iter->first;
		std::shared_ptr<data_wrapper<udp_server>> wrapper_ptr = iter->second;

		std::scoped_lock locker_wrapper_session_map_to_tcp{ mutex_wrapper_session_map_to_target_udp };
		std::shared_ptr<udp_client> local_session = wrapper_session_map_to_target_udp[wrapper_ptr];
		if (local_session->time_gap_of_receive() > TIMEOUT && local_session->time_gap_of_send() > TIMEOUT)
		{
			wrapper_channels.erase(iter);

			std::unique_lock locker_expiring_wrapper{ mutex_expiring_wrapper };
			if (expiring_wrapper.find(wrapper_ptr) == expiring_wrapper.end())
				expiring_wrapper.insert({ wrapper_ptr, right_now() - TIMEOUT });
			locker_expiring_wrapper.unlock();
		}
	}
}

void server_mode::wrapper_loop_updates(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
	{
		return;
	}

	loop_timeout_sessions();

	timer_send_data.expires_after(FINDER_TIMEOUT_INTERVAL);
	timer_send_data.async_wait([this](const asio::error_code &e) { wrapper_loop_updates(e); });
}

void server_mode::expiring_wrapper_loops(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
	{
		return;
	}

	cleanup_expiring_data_connections();

	timer_find_timeout.expires_after(EXPRING_UPDATE_INTERVAL);
	timer_find_timeout.async_wait([this](const asio::error_code &e) { expiring_wrapper_loops(e); });
}

void server_mode::send_stun_request(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
		return;

	if (current_settings.stun_server.empty())
		return;

	resend_stun_8489_request(*udp_servers.begin()->second, current_settings.stun_server, stun_header.get());

	timer_stun.expires_after(STUN_RESEND);
	timer_stun.async_wait([this](const asio::error_code &e) { send_stun_request(e); });
}

server_mode::~server_mode()
{
	timer_send_data.cancel();
	timer_find_timeout.cancel();
	timer_stun.cancel();
}

bool server_mode::start()
{
	printf("start_up() running in server mode\n");

	udp_callback_t func = std::bind(&server_mode::udp_server_incoming, this, _1, _2, _3, _4);
	std::set<uint16_t> listen_ports;
	if (current_settings.listen_port != 0)
		listen_ports.insert(current_settings.listen_port);

	for (uint16_t port_number = current_settings.listen_port_start; port_number <= current_settings.listen_port_end; ++port_number)
	{
		if (port_number != 0)
			listen_ports.insert(port_number);
	}

	udp::endpoint listen_on_ep(udp::v6(), *listen_ports.begin());
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

	bool running_well = true;
	for (uint16_t port_number : listen_ports)
	{
		listen_on_ep.port(port_number);
		try
		{
			udp_servers.insert({ port_number, std::make_unique<udp_server>(network_io, asio_strand, listen_on_ep, func) });
		}
		catch (std::exception &ex)
		{
			std::cerr << ex.what() << "\tPort Number: " << port_number << std::endl;
			if (!current_settings.log_messages.empty())
				print_message_to_file(ex.what() + ("\tPort Number: " + std::to_string(port_number)) + "\n", current_settings.log_messages);
			running_well = false;
		}
	}

	if (!running_well)
		return running_well;
	
	try
	{
		timer_send_data.expires_after(FINDER_TIMEOUT_INTERVAL);
		timer_send_data.async_wait([this](const asio::error_code &e) { wrapper_loop_updates(e); });

		timer_find_timeout.expires_after(EXPRING_UPDATE_INTERVAL);
		timer_find_timeout.async_wait([this](const asio::error_code &e) { expiring_wrapper_loops(e); });

		if (!current_settings.stun_server.empty())
		{
			stun_header = send_stun_8489_request(*udp_servers.begin()->second, current_settings.stun_server);
			timer_stun.expires_after(std::chrono::seconds(1));
			timer_stun.async_wait([this](const asio::error_code &e) { send_stun_request(e); });
		}
	}
	catch (std::exception &ex)
	{
		std::cerr << ex.what() << std::endl;
		running_well = false;
	}

	return running_well;
}

void server_mode::udp_server_incoming(std::shared_ptr<uint8_t[]> data, size_t data_size, udp::endpoint &&peer, asio::ip::port_type port_number)
{
	if (data_size == 0)
		return;

	uint8_t *data_ptr = data.get();

	if (stun_header != nullptr)
	{
		uint32_t ipv4_address = 0;
		uint16_t ipv4_port = 0;
		std::array<uint8_t, 16> ipv6_address{};
		uint16_t ipv6_port = 0;
		if (rfc8489::unpack_address_port(data_ptr, stun_header->transaction_id_part_1, stun_header->transaction_id_part_2, ipv4_address, ipv4_port, ipv6_address, ipv6_port))
		{
			save_external_ip_address(ipv4_address, ipv4_port, ipv6_address, ipv6_port);
			return;
		}
	}

	auto [error_message, plain_size] = decrypt_data(current_settings.encryption_password, current_settings.encryption, data_ptr, (int)data_size);
	if (!error_message.empty() || plain_size == 0)
		return;

	uint32_t iden = data_wrapper<udp_server>::extract_iden(data_ptr);
	if (iden == 0)
	{
		return;
	}

	std::shared_lock share_locker_wrapper_channels{ mutex_wrapper_channels, std::defer_lock };
	std::unique_lock unique_locker_wrapper_channels{ mutex_wrapper_channels, std::defer_lock };
	share_locker_wrapper_channels.lock();
	auto wrapper_channel_iter = wrapper_channels.find(iden);
	if (wrapper_channel_iter == wrapper_channels.end())
	{
		share_locker_wrapper_channels.unlock();
		unique_locker_wrapper_channels.lock();
		wrapper_channel_iter = wrapper_channels.find(iden);
		if (wrapper_channel_iter == wrapper_channels.end())
		{
			udp_server_incoming_new_connection(data, plain_size, std::move(peer), port_number);
			return;
		}
		unique_locker_wrapper_channels.unlock();
		share_locker_wrapper_channels.lock();
	}

	std::shared_ptr<data_wrapper<udp_server>> wrapper = wrapper_channel_iter->second;
	share_locker_wrapper_channels.unlock();
	auto [packet_timestamp, received_data, received_size] = wrapper->receive_data(data_ptr, plain_size);
	if (received_size == 0)
		return;

	auto timestamp = right_now();
	if (calculate_difference(timestamp, packet_timestamp) > TIME_GAP)
		return;

	{
		std::shared_lock shared_locker_wrapper_session_map_to_source_udp{ mutex_wrapper_session_map_to_source_udp };
		if (auto wrapper_iter = wrapper_session_map_to_source_udp.find(wrapper); wrapper_iter != wrapper_session_map_to_source_udp.end())
		{
			if (wrapper_iter->second != peer)
			{
				shared_locker_wrapper_session_map_to_source_udp.unlock();
				std::unique_lock unique_locker_wrapper_session_map_to_source_udp{ mutex_wrapper_session_map_to_source_udp };
				if (wrapper_iter->second != peer)
					wrapper_iter->second = std::move(peer);
			}
		}
		else
			return;
	}

	wrapper->forwarder_ptr.store(udp_servers[port_number].get());

	std::shared_ptr<udp_client> udp_channel;
	std::shared_lock locker{ mutex_wrapper_session_map_to_target_udp };
	if (auto channel_iter = wrapper_session_map_to_target_udp.find(wrapper); channel_iter != wrapper_session_map_to_target_udp.end())
		udp_channel = channel_iter->second;
	else
		return;
	locker.unlock();
	if (udp_channel == nullptr)
		return;

	udp_channel->async_send_out(data, received_data, received_size, *udp_target);
}

void server_mode::udp_client_incoming(std::shared_ptr<uint8_t[]> data, size_t data_size, udp::endpoint &&peer, asio::ip::port_type port_number, std::shared_ptr<data_wrapper<udp_server>> wrapper_session)
{
	uint8_t *packing_data_ptr = data.get();
	auto packed_data_size = wrapper_session->pack_data(packing_data_ptr, data_size);
	auto [error_message, cipher_size] = encrypt_data(current_settings.encryption_password, current_settings.encryption, packing_data_ptr, (int)packed_data_size);
	if (error_message.empty() && cipher_size > 0)
		wrapper_session->send_data(data, packing_data_ptr, cipher_size, get_remote_address(wrapper_session));
}

void server_mode::udp_server_incoming_new_connection(std::shared_ptr<uint8_t[]> data, size_t data_size, udp::endpoint &&peer, asio::ip::port_type port_number)
{
	if (data_size == 0)
		return;

	uint8_t *data_ptr = data.get();

	uint32_t iden = data_wrapper<udp_server>::extract_iden(data_ptr);
	std::shared_ptr<data_wrapper<udp_server>> wrapper = std::make_shared<data_wrapper<udp_server>>(iden);

	auto [packet_timestamp, received_data, received_size] = wrapper->receive_data(data_ptr, data_size);
	if (received_size == 0)
		return;

	auto timestamp = right_now();
	if (calculate_difference(timestamp, packet_timestamp) > TIME_GAP)
		return;

	std::unique_lock locker_wrapper_session_map_to_source_udp{ mutex_wrapper_session_map_to_source_udp };
	wrapper_session_map_to_source_udp[wrapper] = peer;
	locker_wrapper_session_map_to_source_udp.unlock();
	wrapper->forwarder_ptr.store(udp_servers[port_number].get());

	if (create_new_udp_connection(data, received_data, received_size, wrapper, peer))
	{
		wrapper_channels.insert({ iden, wrapper });
		mutex_wrapper_session_map_to_source_udp.lock();
		wrapper_session_map_to_source_udp[wrapper] = std::move(peer);
		mutex_wrapper_session_map_to_source_udp.unlock();
	}
}

bool server_mode::create_new_udp_connection(std::shared_ptr<uint8_t[]> data, const uint8_t *data_ptr, size_t data_size, std::shared_ptr<data_wrapper<udp_server>> wrapper, const udp::endpoint &peer)
{
	bool connect_success = false;

	udp_callback_t udp_func_ap = [wrapper, this](std::shared_ptr<uint8_t[]> input_data, size_t data_size, udp::endpoint &&peer, asio::ip::port_type port_number)
	{
		udp_client_incoming(input_data, data_size, std::move(peer), port_number, wrapper);
	};
	std::shared_ptr<udp_client> target_connector = std::make_shared<udp_client>(network_io, asio_strand, udp_func_ap);

	asio::error_code ec;
	target_connector->send_out(create_raw_random_data(EMPTY_PACKET_SIZE), local_empty_target, ec);
	if (ec)
		return false;

	if (udp_target != nullptr || update_local_udp_target(target_connector))
	{
		target_connector->async_receive();
		target_connector->async_send_out(data, data_ptr, data_size, *udp_target);
		std::unique_lock locker{ mutex_wrapper_session_map_to_target_udp };
		wrapper_session_map_to_target_udp.insert({ wrapper, target_connector });
		locker.unlock();
		return true;
	}

	if (ec)
	{
		connect_success = false;
	}

	return connect_success;
}

udp::endpoint server_mode::get_remote_address(std::shared_ptr<data_wrapper<udp_server>> wrapper_ptr)
{
	udp::endpoint ep;
	std::shared_lock locker_wrapper_session_map_to_source_udp{ mutex_wrapper_session_map_to_source_udp };
	ep = wrapper_session_map_to_source_udp[wrapper_ptr];
	locker_wrapper_session_map_to_source_udp.unlock();

	return ep;
}

bool server_mode::update_local_udp_target(std::shared_ptr<udp_client> target_connector)
{
	bool connect_success = false;
	asio::error_code ec;
	for (int i = 0; i < RETRY_TIMES; ++i)
	{
		const std::string &destination_address = current_settings.destination_address;
		uint16_t destination_port = current_settings.destination_port;
		udp::resolver::results_type udp_endpoints = target_connector->get_remote_hostname(destination_address, destination_port, ec);
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
			udp_target = std::make_unique<udp::endpoint>(*udp_endpoints.begin());
			connect_success = true;
			break;
		}
	}
	return connect_success;
}

void server_mode::save_external_ip_address(uint32_t ipv4_address, uint16_t ipv4_port, const std::array<uint8_t, 16> &ipv6_address, uint16_t ipv6_port)
{
	if (ipv4_address != 0 && ipv4_port != 0 && (external_ipv4_address.load() != ipv4_address || external_ipv4_port.load() != ipv4_port))
	{
		external_ipv4_address.store(ipv4_address);
		external_ipv4_port.store(ipv4_port);
		std::stringstream ss;
		ss << "External IPv4 Address: " << asio::ip::make_address_v4(ipv4_address) << "\n";
		ss << "External IPv4 Port: " << ipv4_port << "\n";
		std::string message = ss.str();
		if (!current_settings.log_ip_address.empty())
			print_ip_to_file(message, current_settings.log_ip_address);
		std::cout << message;
	}

	std::shared_lock locker(mutex_ipv6);
	if (ipv6_address != zero_value_array && ipv6_port != 0 && (external_ipv6_address != ipv6_address || external_ipv6_port != ipv6_port))
	{
		locker.unlock();
		std::unique_lock lock_ipv6(mutex_ipv6);
		external_ipv6_address = ipv6_address;
		lock_ipv6.unlock();
		external_ipv6_port.store(ipv6_port);
		std::stringstream ss;
		ss << "External IPv6 Address: " << asio::ip::make_address_v6(ipv6_address) << "\n";
		ss << "External IPv6 Port: " << ipv6_port << "\n";
		std::string message = ss.str();
		if (!current_settings.log_ip_address.empty())
			print_ip_to_file(message, current_settings.log_ip_address);
		std::cout << message;
	}
}
