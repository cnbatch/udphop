#include <algorithm>
#include <iostream>
#include <random>
#include <thread>
#include "relay.hpp"
#include "../shares/data_operations.hpp"

using namespace std::placeholders;
using namespace std::chrono;
using namespace std::literals;

void relay_mode::udp_listener_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint &peer, asio::ip::port_type port_number)
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

	auto [error_message, plain_size] = decrypt_data(current_settings.ingress->encryption_password, current_settings.ingress->encryption, data_ptr, (int)data_size);
	if (!error_message.empty() || plain_size == 0)
		return;

	udp_listener_incoming_unpack(std::move(data), plain_size, peer, port_number);
}

void relay_mode::udp_listener_incoming_unpack(std::unique_ptr<uint8_t[]> data, size_t plain_size, const udp::endpoint &peer, asio::ip::port_type port_number)
{
	uint8_t *data_ptr = data.get();
	uint32_t iden = packet::data_wrapper::extract_iden(data_ptr);
	if (iden == 0)
	{
		return;
	}

	std::shared_ptr<udp_mappings> udp_session_ptr = nullptr;

	{
		std::shared_lock share_locker_wrapper_channels{ mutex_udp_session_channels, std::defer_lock };
		std::unique_lock unique_locker_wrapper_channels{ mutex_udp_session_channels, std::defer_lock };
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

	auto [packet_timestamp, received_data, received_size] = udp_session_ptr->wrapper_ptr->receive_data(data_ptr, plain_size);
	if (received_size == 0)
		return;

	if (packet_timestamp != 0)
	{
		auto timestamp = right_now();
		if (calculate_difference(timestamp, packet_timestamp) > TIME_GAP)
			return;

		udp_session_ptr->ingress_sender.store(udp_servers[port_number].get());

		if (udp_session_ptr->egress_forwarder == nullptr)
			return;

		if (current_settings.ingress->fec_data > 0 && current_settings.ingress->fec_redundant > 0)
		{
			std::pair<std::unique_ptr<uint8_t[]>, size_t> original_data;
			auto [packet_header, fec_data_ptr, fec_data_size] = udp_session_ptr->wrapper_ptr->receive_data_with_fec(data.get(), plain_size);
			uint32_t fec_sn = packet_header.sn;
			uint8_t fec_sub_sn = packet_header.sub_sn;
			if (packet_header.sub_sn >= current_settings.ingress->fec_data)	// redundant data
			{
				original_data.first = std::make_unique<uint8_t[]>(fec_data_size);
				original_data.second = fec_data_size;
				std::copy_n(fec_data_ptr, fec_data_size, original_data.first.get());
				udp_session_ptr->fec_ingress_control.fec_rcv_cache[fec_sn][fec_sub_sn] = std::move(original_data);
				fec_find_missings_via_listener(udp_session_ptr, udp_session_ptr->fec_ingress_control, fec_sn, current_settings.ingress->fec_data);
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
				fec_find_missings_via_listener(udp_session_ptr, udp_session_ptr->fec_ingress_control, fec_sn, current_settings.ingress->fec_data);
			}
		}

		if (current_settings.ingress->fec_data == 0 || current_settings.ingress->fec_redundant == 0)
		{
			std::vector<uint8_t> packed_original_data = udp_session_ptr->wrapper_ptr->pack_data(received_data, received_size);
			data_sender_via_forwarder(udp_session_ptr, std::move(packed_original_data));
		}
		else
		{
			std::unique_ptr<uint8_t[]> new_data = std::make_unique<uint8_t[]>(received_size + BUFFER_EXPAND_SIZE);
			std::copy(received_data, received_data + received_size, new_data.get());
			fec_maker_via_forwarder(udp_session_ptr, std::move(new_data), received_size);
		}

		udp_session_ptr->last_ingress_receive_time.store(right_now());
		udp_session_ptr->last_egress_send_time.store(right_now());
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

void relay_mode::udp_listener_incoming_new_connection(std::unique_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint &peer, asio::ip::port_type port_number)
{
	if (data_size == 0)
		return;

	uint8_t *data_ptr = data.get();

	uint32_t iden = packet::data_wrapper::extract_iden(data_ptr);
	std::shared_ptr<udp_mappings> udp_session_ptr = std::make_shared<udp_mappings>();
	std::shared_ptr<packet::data_wrapper> data_wrapper_ptr = std::make_shared<packet::data_wrapper>(iden, udp_session_ptr);
	udp_session_ptr->wrapper_ptr = data_wrapper_ptr;
	udp_session_channels[iden] = udp_session_ptr;

	auto [packet_timestamp, received_data, received_size] = data_wrapper_ptr->receive_data(data_ptr, data_size);
	if (received_size == 0)
		return;

	auto timestamp = right_now();
	if (calculate_difference(timestamp, packet_timestamp) > TIME_GAP)
		return;

	std::unique_lock locker_wrapper_session_map_to_source_udp{ udp_session_ptr->mutex_ingress_endpoint };
	udp_session_ptr->ingress_source_endpoint = peer;
	locker_wrapper_session_map_to_source_udp.unlock();
	udp_session_ptr->ingress_sender.store(udp_servers[port_number].get());

	const std::string &destination_address = current_settings.egress->destination_address;
	uint16_t destination_port = current_settings.egress->destination_port;
	if (destination_port == 0)
		destination_port = generate_new_port_number(current_settings.egress->destination_port_start, current_settings.egress->destination_port_end);

	std::shared_ptr<forwarder> udp_forwarder = nullptr;
	try
	{
		auto udp_func = std::bind(&relay_mode::udp_forwarder_incoming_to_udp, this, _1, _2, _3, _4, _5);
		udp_forwarder = std::make_shared<forwarder>(io_context, sequence_task_pool_peer, task_limit, udp_session_ptr, udp_func, current_settings.egress->ip_version_only);
		if (udp_forwarder == nullptr)
			return;
	}
	catch (std::exception &ex)
	{
		std::string error_message = time_to_string_with_square_brackets() + "Cannot create new connection, error: " + ex.what() + "\n";
		std::cerr << error_message;
		print_message_to_file(error_message, current_settings.log_messages);
	}

	bool success = get_udp_target(udp_forwarder, udp_session_ptr->egress_target_endpoint);
	if (!success)
		return;

	udp_session_ptr->changeport_timestamp.store(right_now() + current_settings.egress->dynamic_port_refresh);
	udp_session_ptr->egress_forwarder = udp_forwarder;
	udp_session_ptr->egress_previous_target_endpoint = udp_session_ptr->egress_target_endpoint;

	std::unique_ptr<uint8_t[]> new_data = std::make_unique<uint8_t[]>(received_size + BUFFER_EXPAND_SIZE);
	uint8_t *packing_data_ptr = new_data.get();
	std::copy(received_data, received_data + received_size, packing_data_ptr);
	size_t packed_data_size = data_wrapper_ptr->pack_data(packing_data_ptr, received_size);
	auto [error_message, cipher_size] = encrypt_data(current_settings.egress->encryption_password, current_settings.egress->encryption, packing_data_ptr, (int)packed_data_size);
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

	if (current_settings.egress->fec_data > 0 && current_settings.egress->fec_redundant > 0)
	{
		size_t K = current_settings.egress->fec_data;
		size_t N = K + current_settings.egress->fec_redundant;
		udp_session_ptr->fec_egress_control.fecc.reset_martix(K, N);
	}

	udp_session_ptr->last_ingress_receive_time.store(right_now());
	udp_session_ptr->last_egress_send_time.store(right_now());
}

void relay_mode::udp_forwarder_incoming_to_udp(std::weak_ptr<udp_mappings> udp_session_weak_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint & peer, asio::ip::port_type local_port_number)
{
	std::shared_ptr<udp_mappings> udp_session_ptr = udp_session_weak_ptr.lock();
	if (data_size == 0 || udp_session_ptr == nullptr || data == nullptr)
		return;

	if (data_size < RAW_HEADER_SIZE)
		return;

	uint8_t *data_ptr = data.get();
	auto [error_message, plain_size] = decrypt_data(current_settings.encryption_password, current_settings.encryption, data_ptr, (int)data_size);
	if (!error_message.empty() || plain_size == 0)
		return;

	udp_forwarder_incoming_to_udp_unpack(udp_session_ptr, std::move(data), plain_size, peer, local_port_number);
}

void relay_mode::udp_forwarder_incoming_to_udp_unpack(std::shared_ptr<udp_mappings> udp_session_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint & peer, asio::ip::port_type local_port_number)
{
	if (data_size == 0 || udp_session_ptr == nullptr)
		return;

	uint8_t *data_ptr = data.get();

	uint32_t iden = udp_session_ptr->wrapper_ptr->extract_iden(data_ptr);
	if (udp_session_ptr->wrapper_ptr->get_iden() != iden)
	{
		return;
	}

	auto [packet_timestamp, received_data_ptr, received_size] = udp_session_ptr->wrapper_ptr->receive_data(data_ptr, data_size);
	if (received_size == 0)
		return;

	if (packet_timestamp != 0)
	{
		auto timestamp = right_now();
		if (calculate_difference(timestamp, packet_timestamp) > TIME_GAP)
			return;

		if (current_settings.egress->fec_data > 0 && current_settings.egress->fec_redundant > 0)
		{
			std::pair<std::unique_ptr<uint8_t[]>, size_t> original_data;
			auto [packet_header, fec_data_ptr, fec_data_size] = udp_session_ptr->wrapper_ptr->receive_data_with_fec(data.get(), data_size);
			uint32_t fec_sn = packet_header.sn;
			uint8_t fec_sub_sn = packet_header.sub_sn;
			if (packet_header.sub_sn >= current_settings.egress->fec_data)	// redundant data
			{
				original_data.first = std::make_unique<uint8_t[]>(fec_data_size);
				original_data.second = fec_data_size;
				std::copy_n(fec_data_ptr, fec_data_size, original_data.first.get());
				udp_session_ptr->fec_egress_control.fec_rcv_cache[fec_sn][fec_sub_sn] = std::move(original_data);
				fec_find_missings_via_forwarder(udp_session_ptr, udp_session_ptr->fec_egress_control, fec_sn, current_settings.egress->fec_data);
				return;
			}
			else	// original data
			{
				received_data_ptr = fec_data_ptr;
				received_size = fec_data_size;
				original_data.first = std::make_unique<uint8_t[]>(fec_data_size);
				original_data.second = fec_data_size;
				std::copy_n(fec_data_ptr, fec_data_size, original_data.first.get());
				udp_session_ptr->fec_egress_control.fec_rcv_cache[fec_sn][fec_sub_sn] = std::move(original_data);
				fec_find_missings_via_forwarder(udp_session_ptr, udp_session_ptr->fec_egress_control, fec_sn, current_settings.egress->fec_data);
			}
		}

		std::shared_lock shared_locker_ingress_endpoint{ udp_session_ptr->mutex_ingress_endpoint };
		udp::endpoint udp_endpoint = udp_session_ptr->ingress_source_endpoint;
		shared_locker_ingress_endpoint.unlock();

		std::unique_ptr<uint8_t[]> new_data = std::make_unique<uint8_t[]>(received_size + BUFFER_EXPAND_SIZE);
		if (current_settings.ingress->fec_data == 0 || current_settings.ingress->fec_redundant == 0)
		{
			size_t packed_data_size = udp_session_ptr->wrapper_ptr->pack_data(new_data.get(), received_size);
			data_sender_via_listener(udp_session_ptr.get(), udp_endpoint, std::move(new_data), packed_data_size);
		}
		else
		{
			fec_maker_via_listener(udp_session_ptr, std::move(new_data), received_size);
		}

		udp_session_ptr->last_egress_receive_time.store(right_now());
		udp_session_ptr->last_inress_send_time.store(right_now());
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

bool relay_mode::get_udp_target(std::shared_ptr<forwarder> target_connector, udp::endpoint & udp_target)
{
	if (target_address != nullptr)
	{
		uint16_t destination_port = current_settings.egress->destination_port;
		if (destination_port == 0)
			destination_port = generate_new_port_number(current_settings.egress->destination_port_start, current_settings.egress->destination_port_end);

		udp_target = udp::endpoint(*target_address, destination_port);
		return true;
	}

	return update_udp_target(target_connector, udp_target);
}

bool relay_mode::update_udp_target(std::shared_ptr<forwarder> target_connector, udp::endpoint & udp_target)
{
	uint16_t destination_port = current_settings.egress->destination_port;
	if (destination_port == 0)
		destination_port = generate_new_port_number(current_settings.egress->destination_port_start, current_settings.egress->destination_port_end);

	bool connect_success = false;
	asio::error_code ec;
	for (int i = 0; i <= RETRY_TIMES; ++i)
	{
		const std::string &destination_address = current_settings.egress->destination_address;
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

void relay_mode::save_external_ip_address(uint32_t ipv4_address, uint16_t ipv4_port, const std::array<uint8_t, 16>& ipv6_address, uint16_t ipv6_port)
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

void relay_mode::data_sender_via_listener(udp_mappings *udp_session_ptr, const udp::endpoint &peer, std::unique_ptr<uint8_t[]> data, size_t data_size)
{
	auto [error_message, cipher_size] = encrypt_data(current_settings.ingress->encryption_password, current_settings.ingress->encryption, data.get(), (int)data_size);
	if (error_message.empty() && cipher_size > 0)
		udp_session_ptr->ingress_sender.load()->async_send_out(std::move(data), cipher_size, peer);
}

void relay_mode::data_sender_via_listener(udp_mappings *udp_session_ptr, const udp::endpoint &peer, std::vector<uint8_t> &&data)
{
	std::string error_message;
	std::vector<uint8_t> encrypted_data = encrypt_data(current_settings.ingress->encryption_password, current_settings.ingress->encryption, std::move(data), error_message);
	if (error_message.empty() && encrypted_data.size() > 0)
		udp_session_ptr->ingress_sender.load()->async_send_out(std::move(encrypted_data), peer);
}

void relay_mode::data_sender_via_forwarder(std::shared_ptr<udp_mappings> udp_session_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size)
{
	auto [error_message, cipher_size] = encrypt_data(current_settings.egress->encryption_password, current_settings.egress->encryption, data.get(), (int)data_size);
	if (error_message.empty() && cipher_size > 0)
		udp_session_ptr->egress_forwarder->async_send_out(std::move(data), cipher_size, udp_session_ptr->egress_target_endpoint);
	change_new_port(udp_session_ptr);
}

void relay_mode::data_sender_via_forwarder(std::shared_ptr<udp_mappings> udp_session_ptr, std::vector<uint8_t> &&data)
{
	std::string error_message;
	std::vector<uint8_t> encrypted_data = encrypt_data(current_settings.egress->encryption_password, current_settings.egress->encryption, std::move(data), error_message);
	if (error_message.empty() && encrypted_data.size() > 0)
		udp_session_ptr->egress_forwarder->async_send_out(std::move(encrypted_data), udp_session_ptr->egress_target_endpoint);
	change_new_port(udp_session_ptr);
}

void relay_mode::fec_maker_via_listener(std::shared_ptr<udp_mappings> udp_session_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size)
{
	fec_control_data &fec_controllor = udp_session_ptr->fec_ingress_control;

	fec_controllor.fec_snd_cache.emplace_back(clone_into_pair(data.get(), data_size));

	size_t fec_data_buffer_size = udp_session_ptr->wrapper_ptr->pack_data_with_fec(data.get(), data_size, fec_controllor.fec_snd_sn.load(), fec_controllor.fec_snd_sub_sn++);
	data_sender_via_listener(udp_session_ptr.get(), udp_session_ptr->ingress_source_endpoint, std::move(data), fec_data_buffer_size);

	if (fec_controllor.fec_snd_cache.size() == current_settings.ingress->fec_data)
	{
		auto [array_data, fec_align_length, total_size] = compact_into_container(fec_controllor.fec_snd_cache);
		auto redundants = fec_controllor.fecc.encode(array_data.get(), total_size, fec_align_length);
		for (auto &data_ptr : redundants)
		{
			std::vector<uint8_t> fec_redundant_buffer = udp_session_ptr->wrapper_ptr->pack_data_with_fec(
				(const uint8_t *)data_ptr.get(), fec_align_length,
				fec_controllor.fec_snd_sn.load(), fec_controllor.fec_snd_sub_sn++);
			data_sender_via_listener(udp_session_ptr.get(), udp_session_ptr->ingress_source_endpoint, std::move(fec_redundant_buffer));
		}
		fec_controllor.fec_snd_cache.clear();
		fec_controllor.fec_snd_sub_sn.store(0);
		fec_controllor.fec_snd_sn++;
	}
}

void relay_mode::fec_maker_via_forwarder(std::shared_ptr<udp_mappings> udp_session_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size)
{
	fec_control_data &fec_controllor = udp_session_ptr->fec_egress_control;

	fec_controllor.fec_snd_cache.emplace_back(clone_into_pair(data.get(), data_size));

	size_t fec_data_buffer_size = udp_session_ptr->wrapper_ptr->pack_data_with_fec(data.get(), data_size, fec_controllor.fec_snd_sn.load(), fec_controllor.fec_snd_sub_sn++);
	data_sender_via_forwarder(udp_session_ptr, std::move(data), fec_data_buffer_size);

	if (fec_controllor.fec_snd_cache.size() == current_settings.egress->fec_data)
	{
		auto [array_data, fec_align_length, total_size] = compact_into_container(fec_controllor.fec_snd_cache);
		auto redundants = fec_controllor.fecc.encode(array_data.get(), total_size, fec_align_length);
		for (auto &data_ptr : redundants)
		{
			std::vector<uint8_t> fec_redundant_buffer = udp_session_ptr->wrapper_ptr->pack_data_with_fec(
				(const uint8_t *)data_ptr.get(), fec_align_length,
				fec_controllor.fec_snd_sn.load(), fec_controllor.fec_snd_sub_sn++);
			data_sender_via_forwarder(udp_session_ptr, std::move(fec_redundant_buffer));
		}
		fec_controllor.fec_snd_cache.clear();
		fec_controllor.fec_snd_sub_sn.store(0);
		fec_controllor.fec_snd_sn++;
	}
}

void relay_mode::fec_find_missings_via_listener(std::shared_ptr<udp_mappings> udp_session_ptr, fec_control_data &fec_controllor, uint32_t fec_sn, uint8_t max_fec_data_count)
{
	auto data_sender = [this](std::shared_ptr<udp_mappings> udp_session_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size)
		{
			data_sender_via_forwarder(udp_session_ptr, std::move(data), data_size);
		};
	fec_recovery_count_ingress += fec_find_missings(udp_session_ptr, fec_controllor, fec_sn, max_fec_data_count, data_sender);
}

void relay_mode::fec_find_missings_via_forwarder(std::shared_ptr<udp_mappings> udp_session_ptr, fec_control_data &fec_controllor, uint32_t fec_sn, uint8_t max_fec_data_count)
{
	auto data_sender = [this](std::shared_ptr<udp_mappings> udp_session_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size)
		{
		data_sender_via_listener(udp_session_ptr.get(), udp_session_ptr->ingress_source_endpoint, std::move(data), data_size);
		};
	fec_recovery_count_egress += fec_find_missings(udp_session_ptr, fec_controllor, fec_sn, max_fec_data_count, data_sender);
}

size_t relay_mode::fec_find_missings(std::shared_ptr<udp_mappings> udp_session_ptr, fec_control_data &fec_controllor, uint32_t fec_sn, uint8_t max_fec_data_count,
	std::function<void(std::shared_ptr<udp_mappings>, std::unique_ptr<uint8_t[]>, size_t)> sender_func)
{
	size_t fec_recovery_count = 0;
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
			std::unique_ptr<uint8_t[]> new_data = std::make_unique<uint8_t[]>(missed_data_size + BUFFER_EXPAND_SIZE);
			std::copy(missed_data_ptr, missed_data_ptr + missed_data_size, new_data.get());
			sender_func(udp_session_ptr, std::move(new_data), missed_data_size);
			fec_recovery_count++;
		}

		fec_controllor.fec_rcv_restored.insert(sn);
	}

	return fec_recovery_count;
}

void relay_mode::cleanup_expiring_data_connections()
{
	auto time_right_now = right_now();

	std::scoped_lock lockers{ mutex_expiring_sessions, mutex_expiring_forwarders };
	for (auto iter = expiring_udp_sessions.begin(), next_iter = iter; iter != expiring_udp_sessions.end(); iter = next_iter)
	{
		++next_iter;
		std::shared_ptr<udp_mappings> udp_session_ptr = iter->first;
		int64_t expire_time = iter->second;
		uint32_t iden = udp_session_ptr->wrapper_ptr->get_iden();
		int64_t time_elapsed = calculate_difference(time_right_now, expire_time);

		if (time_elapsed > CLEANUP_WAITS / 2 &&
			udp_session_ptr->egress_forwarder != nullptr)
			udp_session_ptr->egress_forwarder->stop();

		if (time_elapsed <= CLEANUP_WAITS)
			continue;

		expiring_udp_sessions.erase(iter);
	}

	for (auto iter = expiring_forwarders.begin(), next_iter = iter; iter != expiring_forwarders.end(); iter = next_iter)
	{
		++next_iter;
		std::shared_ptr<forwarder> forwarder_ptr = iter->first;
		int64_t expire_time = iter->second;

		int64_t time_elapsed = calculate_difference(time_right_now, expire_time);

		if (time_elapsed <= CLEANUP_WAITS / 2)
			continue;

		if (time_elapsed > CLEANUP_WAITS / 2 && time_elapsed < CLEANUP_WAITS)
		{
			forwarder_ptr->stop();
			continue;
		}

		forwarder_ptr->disconnect();
		expiring_forwarders.erase(iter);
	}
}

void relay_mode::loop_timeout_sessions()
{
	std::vector<std::shared_ptr<forwarder>> old_forwarders;

	{
		std::scoped_lock lockers{ mutex_udp_session_channels, mutex_expiring_sessions };
		for (auto iter = udp_session_channels.begin(), next_iter = iter; iter != udp_session_channels.end(); iter = next_iter)
		{
			++next_iter;
			uint32_t iden = iter->first;
			std::shared_ptr<udp_mappings> udp_session_ptr = iter->second;

			if (time_gap_of_ingress_receive(udp_session_ptr.get()) > current_settings.ingress->timeout &&
				time_gap_of_ingress_send(udp_session_ptr.get()) > current_settings.ingress->timeout &&
				time_gap_of_egress_receive(udp_session_ptr.get()) > current_settings.egress->timeout &&
				time_gap_of_egress_send(udp_session_ptr.get()) > current_settings.egress->timeout)
			{
				if (expiring_udp_sessions.find(udp_session_ptr) == expiring_udp_sessions.end())
					expiring_udp_sessions[udp_session_ptr] = right_now();

				old_forwarders.push_back(udp_session_ptr->egress_forwarder);
				udp_session_ptr->egress_forwarder->stop();
				udp_session_ptr->egress_forwarder = nullptr;
				udp_session_channels.erase(iter);
				udp_session_ptr->changeport_timestamp.store(LLONG_MAX);
			}
		}
	}

	if (!old_forwarders.empty())
	{
		std::scoped_lock lock_expiring_forwarders{ mutex_expiring_forwarders };
		for (std::shared_ptr<forwarder> old_forwarder : old_forwarders)
			expiring_forwarders[old_forwarder] = right_now();
	}
}

void relay_mode::loop_keep_alive_ingress()
{
	std::shared_lock locker{ mutex_udp_session_channels };
	for (auto &[iden, udp_session_ptr] : udp_session_channels)
	{
		if (udp_session_ptr->keep_alive_ingress_timestamp.load() < right_now())
			continue;

		std::vector<uint8_t> keep_alive_packet_ingress = create_empty_data(current_settings.ingress->encryption_password, current_settings.ingress->encryption, EMPTY_PACKET_SIZE);
		udp_session_ptr->wrapper_ptr->write_iden(keep_alive_packet_ingress.data());
		udp_session_ptr->ingress_sender.load()->async_send_out(std::move(keep_alive_packet_ingress), udp_session_ptr->ingress_source_endpoint);
		udp_session_ptr->keep_alive_ingress_timestamp += current_settings.ingress->keep_alive;
	}
}

void relay_mode::loop_keep_alive_egress()
{
	std::shared_lock locker{ mutex_udp_session_channels };
	for (auto &[iden, udp_session_ptr] : udp_session_channels)
	{
		if (udp_session_ptr->keep_alive_egress_timestamp.load() < right_now())
			continue;

		std::vector<uint8_t> keep_alive_packet_egress = create_empty_data(current_settings.egress->encryption_password, current_settings.egress->encryption, EMPTY_PACKET_SIZE);
		udp_session_ptr->wrapper_ptr->write_iden(keep_alive_packet_egress.data());
		udp_session_ptr->egress_forwarder->async_send_out(std::move(keep_alive_packet_egress), udp_session_ptr->egress_target_endpoint);
		udp_session_ptr->keep_alive_egress_timestamp += current_settings.egress->keep_alive;
	}
}

void relay_mode::send_stun_request(const asio::error_code & e)
{
	if (e == asio::error::operation_aborted)
		return;

	if (current_settings.ingress->stun_server.empty())
		return;

	resend_stun_8489_request(*udp_servers.begin()->second, current_settings.ingress->stun_server, stun_header.get(), current_settings.ingress->ip_version_only);

	timer_stun.expires_after(STUN_RESEND);
	timer_stun.async_wait([this](const asio::error_code &e) { send_stun_request(e); });
}

void relay_mode::find_expires(const asio::error_code & e)
{
	if (e == asio::error::operation_aborted)
	{
		return;
	}

	loop_timeout_sessions();

	timer_find_timeout.expires_after(FINDER_TIMEOUT_INTERVAL);
	timer_find_timeout.async_wait([this](const asio::error_code &e) { find_expires(e); });
}

void relay_mode::expiring_wrapper_loops(const asio::error_code & e)
{
	if (e == asio::error::operation_aborted)
	{
		return;
	}

	cleanup_expiring_data_connections();

	timer_expiring_sessions.expires_after(EXPRING_UPDATE_INTERVAL);
	timer_expiring_sessions.async_wait([this](const asio::error_code &e) { expiring_wrapper_loops(e); });
}

void relay_mode::change_new_port(std::shared_ptr<udp_mappings> udp_mappings_ptr)
{
	if (udp_mappings_ptr->changeport_timestamp.load() > right_now())
		return;
	udp_mappings_ptr->changeport_timestamp += current_settings.egress->dynamic_port_refresh;

	uint32_t iden = udp_mappings_ptr->wrapper_ptr->get_iden();
	asio::error_code ec;

	std::shared_ptr<forwarder> udp_forwarder = nullptr;
	try
	{
		auto udp_func = std::bind(&relay_mode::udp_forwarder_incoming_to_udp, this, _1, _2, _3, _4, _5);
		udp_forwarder = std::make_shared<forwarder>(io_context, sequence_task_pool_peer, task_limit, udp_mappings_ptr, udp_func, current_settings.egress->ip_version_only);
		if (udp_forwarder == nullptr)
			return;
	}
	catch (std::exception &ex)
	{
		std::string error_message = time_to_string_with_square_brackets() + "Cannot switch to new port, error: " + ex.what() + "\n";
		std::cerr << error_message;
		print_message_to_file(error_message, current_settings.log_messages);
		return;
	}

	uint16_t destination_port_start = current_settings.egress->destination_port_start;
	uint16_t destination_port_end = current_settings.egress->destination_port_end;
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
	std::vector<uint8_t> keep_alive_packet = create_empty_data(current_settings.egress->encryption_password, current_settings.egress->encryption, EMPTY_PACKET_SIZE);
	udp_mappings_ptr->wrapper_ptr->write_iden(keep_alive_packet.data());

	if (current_settings.egress->ip_version_only == ip_only_options::ipv4)
		new_forwarder->send_out(std::move(keep_alive_packet), local_empty_target_v4, ec);
	else
		new_forwarder->send_out(std::move(keep_alive_packet), local_empty_target_v6, ec);

	if (ec)
		return;

	new_forwarder->async_receive();

	std::shared_ptr<forwarder> old_forwarder = udp_mappings_ptr->egress_forwarder;
	udp_mappings_ptr->egress_forwarder = new_forwarder;

	std::scoped_lock lock_expiring_forwarders{ mutex_expiring_forwarders };
	if (expiring_forwarders.find(old_forwarder) == expiring_forwarders.end())
		expiring_forwarders.insert({ old_forwarder, right_now() });
}

void relay_mode::keep_alive_ingress(const asio::error_code & e)
{
	if (e == asio::error::operation_aborted)
	{
		return;
	}

	loop_keep_alive_ingress();

	timer_keep_alive_ingress.expires_after(KEEP_ALIVE_UPDATE_INTERVAL);
	timer_keep_alive_ingress.async_wait([this](const asio::error_code &e) { keep_alive_ingress(e); });
}

void relay_mode::keep_alive_egress(const asio::error_code & e)
{
	if (e == asio::error::operation_aborted)
	{
		return;
	}

	loop_keep_alive_egress();

	timer_keep_alive_egress.expires_after(KEEP_ALIVE_UPDATE_INTERVAL);
	timer_keep_alive_egress.async_wait([this](const asio::error_code &e) { keep_alive_egress(e); });
}

void relay_mode::log_status(const asio::error_code & e)
{
	if (e == asio::error::operation_aborted)
		return;

	loop_get_status();

	timer_status_log.expires_after(LOGGING_GAP);
	timer_status_log.async_wait([this](const asio::error_code& e) { log_status(e); });
}

void relay_mode::loop_get_status()
{
	std::string output_text = time_to_string_with_square_brackets() + "Summary of " + current_settings.config_filename + "\n";
#ifdef __cpp_lib_format
	output_text += std::format("[Client <-> This] FEC recover: {}\t [This <-> Remote] FEC recover: {}\n",
		fec_recovery_count_ingress.exchange(0), fec_recovery_count_egress.exchange(0));
#else
	std::ostringstream oss;
	oss << "[Client <-> This] FEC recover: " << fec_recovery_count_ingress.exchange(0) <<
		"\t [This <-> Remote] FEC recover: " << fec_recovery_count_egress.exchange(0) << "\n";
	output_text += oss.str();
#endif

	if (!current_settings.log_status.empty())
		print_status_to_file(output_text, current_settings.log_status);
	std::cout << output_text << std::endl;
}

relay_mode::~relay_mode()
{
	timer_expiring_sessions.cancel();
	timer_find_timeout.cancel();
	timer_stun.cancel();
	timer_keep_alive_ingress.cancel();
	timer_keep_alive_egress.cancel();
	timer_status_log.cancel();
}

bool relay_mode::start()
{
	std::cout << app_name << " is running in relay mode\n";

	udp_callback_t func = std::bind(&relay_mode::udp_listener_incoming, this, _1, _2, _3, _4);
	std::set<uint16_t> listen_ports;
	if (current_settings.ingress->listen_port != 0)
		listen_ports.insert(current_settings.ingress->listen_port);

	for (uint16_t port_number = current_settings.ingress->listen_port_start; port_number <= current_settings.ingress->listen_port_end; ++port_number)
	{
		if (port_number != 0)
			listen_ports.insert(port_number);
	}

	udp::endpoint listen_on_ep;
	if (current_settings.ingress->ip_version_only == ip_only_options::ipv4)
		listen_on_ep = udp::endpoint(udp::v4(), *listen_ports.begin());
	else
		listen_on_ep = udp::endpoint(udp::v6(), *listen_ports.begin());

	if (!current_settings.ingress->listen_on.empty())
	{
		asio::error_code ec;
		asio::ip::address local_address = asio::ip::make_address(current_settings.ingress->listen_on, ec);
		if (ec)
		{
			std::string error_message = time_to_string_with_square_brackets() + "Listen Address incorrect - " + current_settings.listen_on + "\n";
			std::cerr << error_message;
			print_message_to_file(error_message, current_settings.log_messages);
			return false;
		}

		if (local_address.is_v4() && current_settings.ingress->ip_version_only == ip_only_options::not_set)
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
			stun_header = send_stun_8489_request(*udp_servers.begin()->second, current_settings.ingress->stun_server, current_settings.ingress->ip_version_only);
			timer_stun.expires_after(std::chrono::seconds(1));
			timer_stun.async_wait([this](const asio::error_code &e) { send_stun_request(e); });
		}

		if (current_settings.ingress->keep_alive > 0)
		{
			timer_keep_alive_ingress.expires_after(KEEP_ALIVE_UPDATE_INTERVAL);
			timer_keep_alive_ingress.async_wait([this](const asio::error_code& e) { keep_alive_ingress(e); });
		}
		if (current_settings.egress->keep_alive > 0)
		{
			timer_keep_alive_egress.expires_after(KEEP_ALIVE_UPDATE_INTERVAL);
			timer_keep_alive_egress.async_wait([this](const asio::error_code& e) { keep_alive_egress(e); });
		}

		if (!current_settings.log_status.empty())
		{
			timer_status_log.expires_after(LOGGING_GAP);
			timer_status_log.async_wait([this](const asio::error_code& e) { log_status(e); });
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

