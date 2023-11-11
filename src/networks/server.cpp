#include <algorithm>
#include <iostream>
#include <random>
#include <thread>
#include "server.hpp"
#include "../shares/data_operations.hpp"

using namespace std::placeholders;
using namespace std::chrono;
using namespace std::literals;


void server_mode::udp_server_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type port_number)
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
		if (rfc8489::unpack_address_port(data_ptr, stun_header.get(), ipv4_address, ipv4_port, ipv6_address, ipv6_port))
		{
			save_external_ip_address(ipv4_address, ipv4_port, ipv6_address, ipv6_port);
			return;
		}
	}

	if (data_size < RAW_HEADER_SIZE)
		return;

	auto [error_message, plain_size] = decrypt_data(current_settings.encryption_password, current_settings.encryption, data_ptr, (int)data_size);
	if (!error_message.empty() || plain_size == 0)
		return;

	udp_server_incoming_unpack(std::move(data), plain_size, peer, port_number);
}

void server_mode::udp_server_incoming_unpack(std::unique_ptr<uint8_t[]> data, size_t plain_size, udp::endpoint peer, asio::ip::port_type port_number)
{
	uint8_t *data_ptr = data.get();
	uint32_t iden = packet::data_wrapper::extract_iden(data_ptr);
	if (iden == 0)
	{
		return;
	}

	std::shared_ptr<udp_mappings> udp_session_ptr = nullptr;

	{
		std::shared_lock share_locker_wrapper_channels{ mutex_wrapper_channels, std::defer_lock };
		std::unique_lock unique_locker_wrapper_channels{ mutex_wrapper_channels, std::defer_lock };
		share_locker_wrapper_channels.lock();
		auto wrapper_channel_iter = udp_session_channels.find(iden);
		if (wrapper_channel_iter == udp_session_channels.end())
		{
			share_locker_wrapper_channels.unlock();
			unique_locker_wrapper_channels.lock();
			wrapper_channel_iter = udp_session_channels.find(iden);
			if (wrapper_channel_iter == udp_session_channels.end())
			{
				udp_server_incoming_new_connection(std::move(data), plain_size, peer, port_number);
				return;
			}
			else
			{
				udp_session_ptr = wrapper_channel_iter->second;
			}
		}
		else
		{
			udp_session_ptr = wrapper_channel_iter->second;
		}
	}

	auto [packet_timestamp, received_data, received_size] = udp_session_ptr->wrapper_ptr->receive_data(data_ptr, plain_size);
	if (received_size == 0)
		return;

	if (packet_timestamp != 0)
	{
		auto timestamp = right_now();
		if (calculate_difference(timestamp, packet_timestamp) > TIME_GAP)
			return;

		udp_session_ptr->ingress_sender.store(udp_servers[port_number].get());

		udp_client *udp_channel = udp_session_ptr->local_udp.get();
		if (udp_channel == nullptr)
			return;

		udp_channel->async_send_out(std::move(data), received_data, received_size, *udp_target);
	}

	std::shared_lock shared_locker_ingress_endpoint{ udp_session_ptr->mutex_ingress_endpoint };
	if (udp_session_ptr->ingress_source_endpoint != peer)
	{
		shared_locker_ingress_endpoint.unlock();
		std::unique_lock unique_locker_ingress_endpoint{ udp_session_ptr->mutex_ingress_endpoint };
		if (udp_session_ptr->ingress_source_endpoint != peer)
			udp_session_ptr->ingress_source_endpoint = peer;
	}
}

void server_mode::udp_client_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type port_number, std::weak_ptr<udp_mappings> udp_session_weak_ptr)
{
	uint8_t *packing_data_ptr = data.get();
	std::shared_ptr<udp_mappings> udp_session_ptr = udp_session_weak_ptr.lock();
	if (packing_data_ptr == nullptr || udp_session_ptr == nullptr)
		return;

	std::shared_lock shared_locker_ingress_endpoint{ udp_session_ptr->mutex_ingress_endpoint };
	udp::endpoint udp_endpoint = udp_session_ptr->ingress_source_endpoint;
	shared_locker_ingress_endpoint.unlock();

	auto packed_data_size = udp_session_ptr->wrapper_ptr->pack_data(packing_data_ptr, data_size);
	auto [error_message, cipher_size] = encrypt_data(current_settings.encryption_password, current_settings.encryption, packing_data_ptr, (int)packed_data_size);
	if (error_message.empty() && cipher_size > 0)
		udp_session_ptr->ingress_sender.load()->async_send_out(std::move(data), packing_data_ptr, cipher_size, udp_endpoint);
}

void server_mode::udp_server_incoming_new_connection(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type port_number)
{
	if (data_size == 0)
		return;

	uint8_t *data_ptr = data.get();

	uint32_t iden = packet::data_wrapper::extract_iden(data_ptr);
	std::shared_ptr<udp_mappings> udp_session_ptr = std::make_shared<udp_mappings>();
	std::shared_ptr<packet::data_wrapper> wrapper = std::make_shared<packet::data_wrapper>(iden, udp_session_ptr);
	udp_session_ptr->wrapper_ptr = wrapper;

	auto [packet_timestamp, received_data, received_size] = wrapper->receive_data(data_ptr, data_size);
	if (received_size == 0)
		return;

	auto timestamp = right_now();
	if (calculate_difference(timestamp, packet_timestamp) > TIME_GAP)
		return;

	std::unique_lock locker_wrapper_session_map_to_source_udp{ udp_session_ptr->mutex_ingress_endpoint };
	udp_session_ptr->ingress_source_endpoint = peer;
	locker_wrapper_session_map_to_source_udp.unlock();
	udp_session_ptr->ingress_sender.store(udp_servers[port_number].get());

	if (create_new_udp_connection(std::move(data), received_data, received_size, udp_session_ptr, peer))
		udp_session_channels[iden] = udp_session_ptr;
}

bool server_mode::create_new_udp_connection(std::unique_ptr<uint8_t[]> data, const uint8_t *data_ptr, size_t data_size, std::shared_ptr<udp_mappings> udp_session_ptr, udp::endpoint peer)
{
	bool connect_success = false;

	std::weak_ptr<udp_mappings> udp_session_weak_ptr = udp_session_ptr;
	udp_callback_t udp_func_ap = [udp_session_weak_ptr, this](std::unique_ptr<uint8_t[]> input_data, size_t data_size, udp::endpoint peer, asio::ip::port_type port_number)
	{
		udp_client_incoming(std::move(input_data), data_size, peer, port_number, udp_session_weak_ptr);
	};
	std::unique_ptr<udp_client> target_connector = std::make_unique<udp_client>(io_context, sequence_task_pool_local, task_limit, udp_func_ap, current_settings.ipv4_only);

	asio::error_code ec;
	if (current_settings.ipv4_only)
		target_connector->send_out(create_raw_random_data(EMPTY_PACKET_SIZE), local_empty_target_v4, ec);
	else
		target_connector->send_out(create_raw_random_data(EMPTY_PACKET_SIZE), local_empty_target_v6, ec);

	if (ec)
		return false;

	if (udp_target != nullptr || update_local_udp_target(target_connector.get()))
	{
		target_connector->async_receive();
		target_connector->async_send_out(std::move(data), data_ptr, data_size, *udp_target);
		udp_session_ptr->local_udp = std::move(target_connector);
		return true;
	}

	if (ec)
	{
		connect_success = false;
	}

	return connect_success;
}

bool server_mode::update_local_udp_target(udp_client *target_connector)
{
	bool connect_success = false;
	asio::error_code ec;
	if (target_connector == nullptr)
		return false;
	for (int i = 0; i < RETRY_TIMES; ++i)
	{
		const std::string &destination_address = current_settings.destination_address;
		uint16_t destination_port = current_settings.destination_port;
		udp::resolver::results_type udp_endpoints = target_connector->get_remote_hostname(destination_address, destination_port, ec);
		if (ec)
		{
			std::string error_message = time_to_string_with_square_brackets() + ec.message();
			std::cerr << error_message << "\n";
			print_message_to_file(error_message + "\n", current_settings.log_messages);
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
			udp_target = std::make_unique<udp::endpoint>(*udp_endpoints.begin());
			connect_success = true;
			break;
		}
	}
	return connect_success;
}

void server_mode::save_external_ip_address(uint32_t ipv4_address, uint16_t ipv4_port, const std::array<uint8_t, 16> &ipv6_address, uint16_t ipv6_port)
{
	std::string v4_info;
	std::string v6_info;

	if (ipv4_address != 0 && ipv4_port != 0 && (external_ipv4_address.load() != ipv4_address || external_ipv4_port.load() != ipv4_port))
	{
		external_ipv4_address.store(ipv4_address);
		external_ipv4_port.store(ipv4_port);
		std::stringstream ss;
		ss << "External IPv4 Address: " << asio::ip::make_address_v4(ipv4_address) << "\n";
		ss << "External IPv4 Port: " << ipv4_port << "\n";
		if (!current_settings.log_ip_address.empty())
			v4_info = ss.str();
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
		if (!current_settings.log_ip_address.empty())
			v6_info = ss.str();
	}

	if (!current_settings.log_ip_address.empty())
	{
		std::string message = "Update Time: " + time_to_string() + "\n" + v4_info + v6_info;
		print_ip_to_file(message, current_settings.log_ip_address);
		std::cout << message;
	}
}

void server_mode::cleanup_expiring_data_connections()
{
	auto time_right_now = right_now();

	std::scoped_lock lockers{ mutex_expiring_wrapper };
	for (auto iter = expiring_udp_sessions.begin(), next_iter = iter; iter != expiring_udp_sessions.end(); iter = next_iter)
	{
		++next_iter;
		std::shared_ptr<udp_mappings> udp_session_ptr = iter->first;
		int64_t expire_time = iter->second;
		uint32_t iden = udp_session_ptr->wrapper_ptr->get_iden();
		if (calculate_difference(time_right_now, expire_time) < CLEANUP_WAITS)
			continue;

		expiring_udp_sessions.erase(iter);
	}
}

void server_mode::loop_timeout_sessions()
{
	std::scoped_lock locker_wrapper_looping{ mutex_wrapper_channels, mutex_expiring_wrapper };
	for (auto iter = udp_session_channels.begin(), next_iter = iter; iter != udp_session_channels.end(); iter = next_iter)
	{
		++next_iter;
		uint32_t iden = iter->first;
		std::shared_ptr<udp_mappings> udp_session_ptr = iter->second;
		udp_client *local_session = udp_session_ptr->local_udp.get();
		if (local_session == nullptr)
			continue;
		if (local_session->time_gap_of_receive() > current_settings.timeout &&
			local_session->time_gap_of_send() > current_settings.timeout)
		{
			local_session->stop();
			udp_session_channels.erase(iter);
			if (expiring_udp_sessions.find(udp_session_ptr) == expiring_udp_sessions.end())
				expiring_udp_sessions.insert({ udp_session_ptr, right_now() - current_settings.timeout });
		}
	}
}

void server_mode::loop_keep_alive()
{
	const std::string &encryption_password = current_settings.encryption_password;
	encryption_mode encryption = current_settings.encryption;

	std::scoped_lock locker_wrapper_looping{ mutex_wrapper_channels };
	for (auto iter = udp_session_channels.begin(), next_iter = iter; iter != udp_session_channels.end(); iter = next_iter)
	{
		++next_iter;
		uint32_t iden = iter->first;
		std::shared_ptr<udp_mappings> udp_session_ptr = iter->second;
		std::vector<uint8_t> keep_alive_packet = create_empty_data(encryption_password, encryption, EMPTY_PACKET_SIZE);
		udp_session_ptr->wrapper_ptr->write_iden(keep_alive_packet.data());
		udp_session_ptr->ingress_sender.load()->async_send_out(std::move(keep_alive_packet), udp_session_ptr->ingress_source_endpoint);
	}
}

void server_mode::find_expires(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
	{
		return;
	}

	loop_timeout_sessions();

	timer_find_timeout.expires_after(FINDER_TIMEOUT_INTERVAL);
	timer_find_timeout.async_wait([this](const asio::error_code &e) { find_expires(e); });
}

void server_mode::expiring_wrapper_loops(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
	{
		return;
	}

	cleanup_expiring_data_connections();

	timer_expiring_sessions.expires_after(EXPRING_UPDATE_INTERVAL);
	timer_expiring_sessions.async_wait([this](const asio::error_code &e) { expiring_wrapper_loops(e); });
}

void server_mode::keep_alive(const asio::error_code& e)
{
	if (e == asio::error::operation_aborted)
	{
		return;
	}

	loop_keep_alive();

	timer_keep_alive.expires_after(seconds{ current_settings.keep_alive });
	timer_keep_alive.async_wait([this](const asio::error_code &e) { keep_alive(e); });
}

void server_mode::send_stun_request(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
		return;

	if (current_settings.stun_server.empty())
		return;

	resend_stun_8489_request(*udp_servers.begin()->second, current_settings.stun_server, stun_header.get(), current_settings.ipv4_only);

	timer_stun.expires_after(STUN_RESEND);
	timer_stun.async_wait([this](const asio::error_code &e) { send_stun_request(e); });
}

server_mode::~server_mode()
{
	timer_expiring_sessions.cancel();
	timer_find_timeout.cancel();
	timer_stun.cancel();
	timer_keep_alive.cancel();
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

	udp::endpoint listen_on_ep;
	if (current_settings.ipv4_only)
		listen_on_ep = udp::endpoint(udp::v4(), *listen_ports.begin());
	else
		listen_on_ep = udp::endpoint(udp::v6(), *listen_ports.begin());

	if (!current_settings.listen_on.empty())
	{
		asio::error_code ec;
		asio::ip::address local_address = asio::ip::make_address(current_settings.listen_on, ec);
		if (ec)
		{
			std::string error_message = time_to_string_with_square_brackets() + "Listen Address incorrect - " + current_settings.listen_on + "\n";
			std::cerr << error_message;
			print_message_to_file(error_message, current_settings.log_messages);
			return false;
		}

		if (local_address.is_v4() && !current_settings.ipv4_only)
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
			udp_servers.insert({ port_number, std::make_unique<udp_server>(network_io, sequence_task_pool_peer, task_limit, listen_on_ep, func) });
		}
		catch (std::exception &ex)
		{
			std::string error_message = time_to_string_with_square_brackets() + ex.what() + ("\tPort Number: " + std::to_string(port_number)) + "\n";
			std::cerr << error_message;
			print_message_to_file(error_message, current_settings.log_messages);
			running_well = false;
		}
	}

	if (!running_well)
		return running_well;

	try
	{
		timer_expiring_sessions.expires_after(EXPRING_UPDATE_INTERVAL);
		timer_expiring_sessions.async_wait([this](const asio::error_code &e) { expiring_wrapper_loops(e); });

		timer_find_timeout.expires_after(FINDER_TIMEOUT_INTERVAL);
		timer_find_timeout.async_wait([this](const asio::error_code &e) { find_expires(e); });

		if (!current_settings.stun_server.empty())
		{
			stun_header = send_stun_8489_request(*udp_servers.begin()->second, current_settings.stun_server, current_settings.ipv4_only);
			timer_stun.expires_after(std::chrono::seconds(1));
			timer_stun.async_wait([this](const asio::error_code &e) { send_stun_request(e); });
		}

		if (current_settings.keep_alive > 0)
		{
			timer_keep_alive.expires_after(seconds{ current_settings.keep_alive });
			timer_keep_alive.async_wait([this](const asio::error_code& e) { keep_alive(e); });
		}
	}
	catch (std::exception &ex)
	{
		std::string error_message = time_to_string_with_square_brackets() + ex.what();
		std::cerr << error_message << std::endl;
		print_message_to_file(error_message + "\n", current_settings.log_messages);
		running_well = false;
	}

	return running_well;
}
