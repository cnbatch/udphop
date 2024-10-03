#include <algorithm>
#include <iostream>
#include <random>
#include <thread>
#include "server.hpp"
#include "../shares/data_operations.hpp"

using namespace std::placeholders;
using namespace std::chrono;
using namespace std::literals;


void server_mode::make_nzero_sessions()
{
	for (auto &[port_number, udp_server] : udp_servers)
	{
		std::shared_ptr<udp_mappings> udp_session_ptr = std::make_shared<udp_mappings>();
		udp_session_ptr->wrapper_ptr = std::make_unique<packet::data_wrapper>(0, udp_session_ptr);
		packet::data_wrapper* data_wrapper_ptr = udp_session_ptr->wrapper_ptr.get();
		udp_session_ptr->ingress_sender.store(udp_server.get());
		udp_zero_sessions[port_number] = udp_session_ptr;
	
		if (current_settings.fec_data > 0 && current_settings.fec_redundant > 0)
		{
			size_t K = current_settings.fec_data;
			size_t N = K + current_settings.fec_redundant;
			udp_session_ptr->fec_ingress_control.fecc.reset_martix(K, N);
		}
	}
}

void server_mode::udp_listener_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint &peer, asio::ip::port_type port_number)
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

	udp_listener_incoming_unpack(std::move(data), plain_size, peer, port_number);
}

void server_mode::udp_listener_incoming_unpack(std::unique_ptr<uint8_t[]> data, size_t plain_size, const udp::endpoint &peer, asio::ip::port_type port_number)
{
	uint8_t *data_ptr = data.get();
	uint32_t iden = packet::data_wrapper::extract_iden(data_ptr);
	if (iden == 0)
	{
		udp_listener_response_test_connection(std::move(data), plain_size, peer, port_number);
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
				udp_listener_incoming_new_connection(std::move(data), plain_size, peer, port_number);
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

	auto [packet_timestamp, feature_value, received_data, received_size] = udp_session_ptr->wrapper_ptr->receive_data(data_ptr, plain_size);
	if (received_size == 0 || packet_timestamp == 0 || feature_value == feature::test_connection)
		return;

	auto timestamp = right_now();
	if (calculate_difference<int64_t>((uint32_t)timestamp, packet_timestamp) > TIME_GAP)
		return;

	udp_session_ptr->ingress_sender.store(udp_servers[port_number].get());

	udp_client *udp_channel = udp_session_ptr->local_udp.get();
	if (udp_channel == nullptr)
		return;

	if (current_settings.fec_data > 0 && current_settings.fec_redundant > 0)
	{
		std::pair<std::unique_ptr<uint8_t[]>, size_t> original_data;
		auto [packet_header, fec_data_ptr, fec_data_size] = udp_session_ptr->wrapper_ptr->receive_data_with_fec(data.get(), plain_size);
		uint32_t fec_sn = packet_header.sn;
		uint8_t fec_sub_sn = packet_header.sub_sn;
		if (packet_header.sub_sn >= current_settings.fec_data)	// redundant data
		{
			original_data.first = std::make_unique<uint8_t[]>(fec_data_size);
			original_data.second = fec_data_size;
			std::copy_n(fec_data_ptr, fec_data_size, original_data.first.get());
			udp_session_ptr->fec_ingress_control.fec_rcv_cache[fec_sn][fec_sub_sn] = std::move(original_data);
			fec_find_missings(udp_session_ptr.get(), udp_session_ptr->fec_ingress_control, fec_sn, current_settings.fec_data);
			return;
		}
		else	// original data
		{
			received_data = fec_data_ptr;
			received_size = fec_data_size;
			original_data.first = std::make_unique<uint8_t[]>(fec_data_size);
			original_data.second = fec_data_size;
			std::copy_n(fec_data_ptr, fec_data_size, original_data.first.get());
			udp_session_ptr->fec_ingress_control.fec_rcv_cache[fec_sn][fec_sub_sn] = std::move(original_data);
			fec_find_missings(udp_session_ptr.get(), udp_session_ptr->fec_ingress_control, fec_sn, current_settings.fec_data);
		}
	}

	if (feature_value != feature::test_connection)
	{
		std::shared_lock shared_locker_ingress_endpoint{ udp_session_ptr->mutex_ingress_endpoint };
		if (udp_session_ptr->ingress_source_endpoint != peer)
		{
			shared_locker_ingress_endpoint.unlock();
			std::unique_lock unique_locker_ingress_endpoint{ udp_session_ptr->mutex_ingress_endpoint };
			if (udp_session_ptr->ingress_source_endpoint != peer)
				udp_session_ptr->ingress_source_endpoint = peer;
		}
	}

	switch (feature_value)
	{
	case feature::keep_alive:
		if (current_settings.fec_data == 0 || current_settings.fec_redundant == 0)
		{
			auto [response_packet, response_packet_size] = udp_session_ptr->wrapper_ptr->create_keep_alive_response_packet();
			data_sender(udp_session_ptr.get(), peer, std::move(response_packet), response_packet_size);
		}
		else
		{
			auto [response_packet, response_packet_size] = udp_session_ptr->wrapper_ptr->create_random_small_packet();
			fec_maker(udp_session_ptr, feature::keep_alive_response, std::move(response_packet), response_packet_size);
		}
		break;
	case feature::test_connection:
		break;
	case feature::keep_alive_response:
		break;
	case feature::raw_data:
		udp_channel->async_send_out(std::move(data), received_data, received_size, *udp_target);
		udp_session_ptr->last_ingress_receive_time.store(right_now());
		udp_session_ptr->last_egress_send_time.store(right_now());
		break;
	default:
		return;
		break;
	}
}

void server_mode::udp_connector_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint &peer, asio::ip::port_type port_number, std::weak_ptr<udp_mappings> udp_session_weak_ptr)
{
	std::shared_ptr<udp_mappings> udp_session_ptr = udp_session_weak_ptr.lock();
	if (data == nullptr || udp_session_ptr == nullptr)
		return;

	std::shared_lock shared_locker_ingress_endpoint{ udp_session_ptr->mutex_ingress_endpoint };
	udp::endpoint udp_endpoint = udp_session_ptr->ingress_source_endpoint;
	shared_locker_ingress_endpoint.unlock();

	if (current_settings.fec_data == 0 || current_settings.fec_redundant == 0)
	{
		size_t packed_data_size = udp_session_ptr->wrapper_ptr->pack_data(feature::raw_data, data.get(), data_size);
		data_sender(udp_session_ptr.get(), udp_endpoint, std::move(data), packed_data_size);
	}
	else
	{
		fec_maker(udp_session_ptr, feature::raw_data, std::move(data), data_size);
	}

	udp_session_ptr->last_egress_receive_time.store(right_now());
	udp_session_ptr->last_inress_send_time.store(right_now());
}

void server_mode::udp_listener_incoming_new_connection(std::unique_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint &peer, asio::ip::port_type port_number)
{
	if (data_size == 0)
		return;

	uint8_t *data_ptr = data.get();

	uint32_t iden = packet::data_wrapper::extract_iden(data_ptr);
	std::shared_ptr<udp_mappings> udp_session_ptr = std::make_shared<udp_mappings>();
	udp_session_ptr->wrapper_ptr = std::make_unique<packet::data_wrapper>(iden, udp_session_ptr);
	packet::data_wrapper *data_wrapper_ptr = udp_session_ptr->wrapper_ptr.get();

	auto [packet_timestamp, feature_value, received_data, received_size] = data_wrapper_ptr->receive_data(data_ptr, data_size);
	if (received_size == 0)
		return;

	auto timestamp = right_now();
	if (calculate_difference<int64_t>((uint32_t)timestamp, packet_timestamp) > TIME_GAP)
		return;

	std::unique_lock locker_wrapper_session_map_to_source_udp{ udp_session_ptr->mutex_ingress_endpoint };
	udp_session_ptr->ingress_source_endpoint = peer;
	locker_wrapper_session_map_to_source_udp.unlock();
	udp_session_ptr->ingress_sender.store(udp_servers[port_number].get());

	if (current_settings.fec_data > 0 && current_settings.fec_redundant > 0)
	{
		size_t K = current_settings.fec_data;
		size_t N = K + current_settings.fec_redundant;
		udp_session_ptr->fec_ingress_control.fecc.reset_martix(K, N);
	}

	switch (feature_value)
	{
	case feature::keep_alive:
		if (current_settings.fec_data == 0 || current_settings.fec_redundant == 0)
		{
			auto [response_packet, response_packet_size] = udp_session_ptr->wrapper_ptr->create_keep_alive_response_packet();
			data_sender(udp_session_ptr.get(), peer, std::move(response_packet), response_packet_size);
		}
		else
		{
			auto [response_packet, response_packet_size] = udp_session_ptr->wrapper_ptr->create_random_small_packet();
			fec_maker(udp_session_ptr, feature::keep_alive_response, std::move(response_packet), response_packet_size);
		}
		break;
	case feature::test_connection:
		if (current_settings.fec_data == 0 || current_settings.fec_redundant == 0)
		{
			auto [response_packet, response_packet_size] = udp_session_ptr->wrapper_ptr->create_test_connection_packet();
			data_sender(udp_session_ptr.get(), peer, std::move(response_packet), response_packet_size);
		}
		else
		{
			auto [response_packet, response_packet_size] = udp_session_ptr->wrapper_ptr->create_random_small_packet();
			fec_test_maker(udp_session_ptr, peer, feature::test_connection, std::move(response_packet), response_packet_size);
		}
		break;
	case feature::keep_alive_response:
		break;
	case feature::raw_data:
		if (create_new_udp_connection(std::move(data), received_data, received_size, udp_session_ptr, peer))
			udp_session_channels[iden] = udp_session_ptr;
		break;
	default:
		break;
	}
}

void server_mode::udp_listener_response_test_connection(std::unique_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint &peer, asio::ip::port_type port_number)
{
	if (data_size == 0)
		return;

	uint8_t *data_ptr = data.get();
	std::shared_ptr<udp_mappings> udp_session_ptr = udp_zero_sessions[port_number];
	packet::data_wrapper *data_wrapper_ptr = udp_session_ptr->wrapper_ptr.get();

	auto [packet_timestamp, feature_value, received_data, received_size] = data_wrapper_ptr->receive_data(data_ptr, data_size);
	if (received_size == 0 || feature_value != feature::test_connection)
		return;

	auto timestamp = right_now();
	if (calculate_difference<int64_t>((uint32_t)timestamp, packet_timestamp) > TIME_GAP)
		return;

	std::unique_lock locker_wrapper_session_map_to_source_udp{ udp_session_ptr->mutex_ingress_endpoint };
	udp_session_ptr->ingress_source_endpoint = peer;
	locker_wrapper_session_map_to_source_udp.unlock();

	uint32_t test_iden = data_wrapper_ptr->unpack_test_iden(received_data);

	if (current_settings.fec_data == 0 || current_settings.fec_redundant == 0)
	{
		auto [response_packet, response_packet_size] = udp_session_ptr->wrapper_ptr->create_test_connection_packet(test_iden);
		data_sender(udp_session_ptr.get(), peer, std::move(response_packet), response_packet_size);
	}
	else
	{
		auto [response_packet, response_packet_size] = udp_session_ptr->wrapper_ptr->create_small_packet(test_iden);
		fec_test_maker(udp_session_ptr, peer, feature::test_connection, std::move(response_packet), response_packet_size);
	}
}

bool server_mode::create_new_udp_connection(std::unique_ptr<uint8_t[]> data, const uint8_t *data_ptr, size_t data_size, std::shared_ptr<udp_mappings> udp_session_ptr, const udp::endpoint &peer)
{
	bool connect_success = false;

	std::weak_ptr<udp_mappings> udp_session_weak_ptr = udp_session_ptr;
	udp_callback_t udp_func_ap = [udp_session_weak_ptr, this](std::unique_ptr<uint8_t[]> input_data, size_t data_size, udp::endpoint peer, asio::ip::port_type port_number)
	{
		udp_connector_incoming(std::move(input_data), data_size, peer, port_number, udp_session_weak_ptr);
	};
	std::unique_ptr<udp_client> target_connector = std::make_unique<udp_client>(io_context, sequence_task_pool_local, task_limit, udp_func_ap, current_settings.ip_version_only);

	asio::error_code ec;
	if (current_settings.ip_version_only == ip_only_options::ipv4)
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
		udp_session_ptr->last_ingress_receive_time.store(right_now());
		udp_session_ptr->last_egress_send_time.store(right_now());
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

void server_mode::data_sender(udp_mappings *udp_session_ptr, const udp::endpoint &peer, std::unique_ptr<uint8_t[]> data, size_t data_size)
{
	auto [error_message, cipher_size] = encrypt_data(current_settings.encryption_password, current_settings.encryption, data.get(), (int)data_size);
	if (error_message.empty() && cipher_size > 0)
		udp_session_ptr->ingress_sender.load()->async_send_out(std::move(data), cipher_size, peer);
}

void server_mode::data_sender(udp_mappings *udp_session_ptr, const udp::endpoint &peer, std::vector<uint8_t> &&data)
{
	std::string error_message;
	std::vector<uint8_t> encrypted_data = encrypt_data(current_settings.encryption_password, current_settings.encryption, std::move(data), error_message);
	if (error_message.empty() && encrypted_data.size() > 0)
		udp_session_ptr->ingress_sender.load()->async_send_out(std::move(encrypted_data), peer);
}

void server_mode::fec_maker(std::shared_ptr<udp_mappings> udp_session_ptr, feature feature_value, std::unique_ptr<uint8_t[]> data, size_t data_size)
{
	fec_control_data &fec_controllor = udp_session_ptr->fec_ingress_control;

	fec_controllor.fec_snd_cache.emplace_back(clone_into_pair(data.get(), data_size));

	size_t fec_data_buffer_size = udp_session_ptr->wrapper_ptr->pack_data_with_fec(feature_value, data.get(), data_size, fec_controllor.fec_snd_sn.load(), fec_controllor.fec_snd_sub_sn++);
	data_sender(udp_session_ptr.get(), udp_session_ptr->ingress_source_endpoint, std::move(data), fec_data_buffer_size);

	if (fec_controllor.fec_snd_cache.size() == current_settings.fec_data)
	{
		auto [array_data, fec_align_length, total_size] = compact_into_container(fec_controllor.fec_snd_cache);
		auto redundants = fec_controllor.fecc.encode(array_data.get(), total_size, fec_align_length);
		for (auto &data_ptr : redundants)
		{
			std::vector<uint8_t> fec_redundant_buffer = udp_session_ptr->wrapper_ptr->pack_data_with_fec(
				feature_value,
				(const uint8_t *)data_ptr.get(), fec_align_length,
				fec_controllor.fec_snd_sn.load(), fec_controllor.fec_snd_sub_sn++);
			data_sender(udp_session_ptr.get(), udp_session_ptr->ingress_source_endpoint, std::move(fec_redundant_buffer));
		}
		fec_controllor.fec_snd_cache.clear();
		fec_controllor.fec_snd_sub_sn.store(0);
		fec_controllor.fec_snd_sn++;
	}
}

void server_mode::fec_test_maker(std::shared_ptr<udp_mappings> udp_session_ptr, const udp::endpoint &peer, feature feature_value, std::unique_ptr<uint8_t[]> data, size_t data_size)
{
	fec_control_data &fec_controllor = udp_session_ptr->fec_ingress_control;
	size_t fec_data_buffer_size = udp_session_ptr->wrapper_ptr->pack_data_with_fec(feature_value, data.get(), data_size, 0, 0);
	data_sender(udp_session_ptr.get(), peer, std::move(data), fec_data_buffer_size);
}

void server_mode::fec_find_missings(udp_mappings *udp_session_ptr, fec_control_data &fec_controllor, uint32_t fec_sn, uint8_t max_fec_data_count)
{
	for (auto iter = fec_controllor.fec_rcv_cache.begin(), next_iter = iter; iter != fec_controllor.fec_rcv_cache.end(); iter = next_iter)
	{
		++next_iter;
		auto sn = iter->first;
		auto &mapped_data = iter->second;
		if (mapped_data.size() < max_fec_data_count)
		{
			if (fec_sn - sn > FEC_WAITS)
			{
				fec_controllor.fec_rcv_cache.erase(iter);
				if (auto rcv_sn_iter = fec_controllor.fec_rcv_restored.find(sn);
					rcv_sn_iter != fec_controllor.fec_rcv_restored.end())
					fec_controllor.fec_rcv_restored.erase(rcv_sn_iter);
			}
			continue;
		}
		if (auto rcv_sn_iter = fec_controllor.fec_rcv_restored.find(sn); rcv_sn_iter != fec_controllor.fec_rcv_restored.end())
		{
			if (fec_sn - sn > FEC_WAITS)
			{
				fec_controllor.fec_rcv_cache.erase(iter);
				fec_controllor.fec_rcv_restored.erase(rcv_sn_iter);
			}
			continue;
		}
		auto [recv_data, fec_align_length] = compact_into_container(mapped_data, max_fec_data_count);
		auto array_data = mapped_pair_to_mapped_pointer(recv_data);
		auto restored_data = fec_controllor.fecc.decode(array_data, fec_align_length);

		for (auto &[i, data] : restored_data)
		{
			auto [missed_data_ptr, missed_data_size] = extract_from_container(data);
			udp_session_ptr->local_udp->async_send_out(std::move(data), missed_data_ptr, missed_data_size, *udp_target);
			fec_recovery_count++;
		}

		fec_controllor.fec_rcv_restored.insert(sn);
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
		int64_t time_elapsed = calculate_difference(time_right_now, expire_time);

		if (time_elapsed <= CLEANUP_WAITS)
			continue;

		if (time_elapsed < CLEANUP_WAITS)
		{
			udp_session_ptr->local_udp->stop();
			continue;
		}

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

	std::shared_lock locker_wrapper_looping{ mutex_wrapper_channels };
	for (auto &[iden, udp_session_ptr] :  udp_session_channels)
	{
		if (udp_session_ptr->keep_alive_ingress_timestamp.load() < right_now())
			continue;
		if (current_settings.fec_data == 0 || current_settings.fec_redundant == 0)
		{
			auto [response_packet, response_packet_size] = udp_session_ptr->wrapper_ptr->create_keep_alive_packet();
			data_sender(udp_session_ptr.get(), udp_session_ptr->ingress_source_endpoint, std::move(response_packet), response_packet_size);
		}
		else
		{
			auto [response_packet, response_packet_size] = udp_session_ptr->wrapper_ptr->create_random_small_packet();
			fec_maker(udp_session_ptr, feature::keep_alive, std::move(response_packet), response_packet_size);
		}
		udp_session_ptr->keep_alive_ingress_timestamp += current_settings.keep_alive;
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

void server_mode::keep_alive(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
	{
		return;
	}

	loop_keep_alive();

	timer_keep_alive.expires_after(seconds{ current_settings.keep_alive });
	timer_keep_alive.async_wait([this](const asio::error_code &e) { keep_alive(e); });
}

void server_mode::log_status(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
		return;

	loop_get_status();

	timer_status_log.expires_after(LOGGING_GAP);
	timer_status_log.async_wait([this](const asio::error_code &e) { log_status(e); });
}

void server_mode::loop_get_status()
{
	std::string output_text = time_to_string_with_square_brackets() + "Summary of " + current_settings.config_filename + "\n";
#ifdef __cpp_lib_format
	output_text += std::format("fec recovery: {}\n", fec_recovery_count.exchange(0));
#else
	std::ostringstream oss;
	oss << "fec recovery: " << fec_recovery_count.exchange(0) << "\n";
	output_text += oss.str();
#endif

	if (!current_settings.log_status.empty())
		print_status_to_file(output_text, current_settings.log_status);
	std::cout << output_text << std::endl;
}

void server_mode::send_stun_request(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
		return;

	if (current_settings.stun_server.empty())
		return;

	resend_stun_8489_request(*udp_servers.begin()->second, current_settings.stun_server, stun_header.get(), current_settings.ip_version_only);

	timer_stun.expires_after(STUN_RESEND);
	timer_stun.async_wait([this](const asio::error_code &e) { send_stun_request(e); });
}

server_mode::~server_mode()
{
	timer_expiring_sessions.cancel();
	timer_find_timeout.cancel();
	timer_stun.cancel();
	timer_keep_alive.cancel();
	timer_status_log.cancel();
}

bool server_mode::start()
{
	std::cout << app_name << " is running in server mode\n";

	udp_callback_t func = std::bind(&server_mode::udp_listener_incoming, this, _1, _2, _3, _4);
	std::set<uint16_t> listen_ports;
	if (current_settings.listen_port != 0)
		listen_ports.insert(current_settings.listen_port);

	for (uint16_t port_number = current_settings.listen_port_start; port_number <= current_settings.listen_port_end; ++port_number)
	{
		if (port_number != 0)
			listen_ports.insert(port_number);
	}

	udp::endpoint listen_on_ep;
	if (current_settings.ip_version_only == ip_only_options::ipv4)
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

		if (local_address.is_v4() && current_settings.ip_version_only == ip_only_options::not_set)
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
		make_nzero_sessions();

		timer_expiring_sessions.expires_after(EXPRING_UPDATE_INTERVAL);
		timer_expiring_sessions.async_wait([this](const asio::error_code &e) { expiring_wrapper_loops(e); });

		timer_find_timeout.expires_after(FINDER_TIMEOUT_INTERVAL);
		timer_find_timeout.async_wait([this](const asio::error_code &e) { find_expires(e); });

		if (!current_settings.stun_server.empty())
		{
			stun_header = send_stun_8489_request(*udp_servers.begin()->second, current_settings.stun_server, current_settings.ip_version_only);
			timer_stun.expires_after(std::chrono::seconds(1));
			timer_stun.async_wait([this](const asio::error_code &e) { send_stun_request(e); });
		}

		if (current_settings.keep_alive > 0)
		{
			timer_keep_alive.expires_after(seconds{ current_settings.keep_alive });
			timer_keep_alive.async_wait([this](const asio::error_code &e) { keep_alive(e); });
		}

		if (!current_settings.log_status.empty())
		{
			timer_status_log.expires_after(LOGGING_GAP);
			timer_status_log.async_wait([this](const asio::error_code &e) { log_status(e); });
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
