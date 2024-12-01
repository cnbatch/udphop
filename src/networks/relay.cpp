#include <algorithm>
#include <iostream>
#include <random>
#include <thread>
#include "relay.hpp"
#include "../shares/data_operations.hpp"

using namespace std::placeholders;
using namespace std::chrono;
using namespace std::literals;

void relay_mode::make_nzero_sessions()
{
	for (auto &udp_server_ptr : udp_servers)
	{
		std::shared_ptr<udp_mappings> udp_session_ptr = std::make_shared<udp_mappings>();
		udp_session_ptr->wrapper_ptr = std::make_unique<packet::data_wrapper>(0, udp_session_ptr);
		packet::data_wrapper* data_wrapper_ptr = udp_session_ptr->wrapper_ptr.get();
		udp_session_ptr->ingress_sender.store(udp_server_ptr.get());
		udp_zero_sessions[udp_server_ptr.get()] = udp_session_ptr;

		if (current_settings.fec_data > 0 && current_settings.fec_redundant > 0)
		{
			size_t K = current_settings.fec_data;
			size_t N = K + current_settings.fec_redundant;
			udp_session_ptr->fec_ingress_control.fecc.reset_martix(K, N);
		}
	}
}

void relay_mode::udp_listener_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint &peer, udp_server *listener_ptr)
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

	if (listener_parallels != nullptr)
	{
		parallel_decrypt_via_listener(std::move(data), data_size, peer, listener_ptr);
		return;
	}

	auto [error_message, plain_size] = decrypt_data(current_settings.ingress->encryption_password, current_settings.ingress->encryption, data_ptr, (int)data_size);
	if (!error_message.empty() || plain_size == 0)
		return;

	udp_listener_incoming_unpack(std::move(data), plain_size, peer, listener_ptr);
}

void relay_mode::udp_listener_incoming_unpack(std::unique_ptr<uint8_t[]> data, size_t plain_size, const udp::endpoint &peer, udp_server *listener_ptr)
{
	uint8_t *data_ptr = data.get();
	uint32_t iden = packet::data_wrapper::extract_iden(data_ptr);
	if (iden == 0)
	{
		udp_listener_response_test_connection(std::move(data), plain_size, peer, listener_ptr);
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
				udp_listener_incoming_new_connection(std::move(data), plain_size, peer, listener_ptr);
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

	udp_session_ptr->ingress_sender.store(listener_ptr);

	if (std::shared_ptr<forwarder> egress_forwarder = std::atomic_load(&(udp_session_ptr->egress_forwarder));
		egress_forwarder == nullptr)
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

	if (std::shared_ptr<udp::endpoint> ingress_source_endpoint = std::atomic_load(&(udp_session_ptr->ingress_source_endpoint));
		ingress_source_endpoint == nullptr || *ingress_source_endpoint != peer)
		std::atomic_store(&(udp_session_ptr->ingress_source_endpoint), std::make_shared<udp::endpoint>(peer));

	switch (feature_value)
	{
	case feature::keep_alive:
		if (current_settings.fec_data == 0 || current_settings.fec_redundant == 0)
		{
			auto [response_packet, response_packet_size] = udp_session_ptr->wrapper_ptr->create_keep_alive_response_packet();
			data_sender_via_listener(udp_session_ptr, peer, std::move(response_packet), response_packet_size);
		}
		else
		{
			auto [response_packet, response_packet_size] = udp_session_ptr->wrapper_ptr->create_random_small_packet();
			fec_maker_via_listener(udp_session_ptr, feature::keep_alive_response, std::move(response_packet), response_packet_size);
		}
		break;
	case feature::test_connection:
		break;
	case feature::keep_alive_response:
		break;
	case feature::raw_data:
		if (current_settings.ingress->fec_data == 0 || current_settings.ingress->fec_redundant == 0)
		{
			auto [packed_original_data, packed_data_size] = udp_session_ptr->wrapper_ptr->pack_data(feature::raw_data, received_data, received_size);
			data_sender_via_forwarder(udp_session_ptr, std::move(packed_original_data), packed_data_size);
		}
		else
		{
			std::unique_ptr<uint8_t[]> new_data = std::make_unique<uint8_t[]>(received_size + BUFFER_EXPAND_SIZE);
			std::copy(received_data, received_data + received_size, new_data.get());
			fec_maker_via_forwarder(udp_session_ptr, feature::raw_data, std::move(new_data), received_size);
		}
		udp_session_ptr->last_ingress_receive_time.store(right_now());
		udp_session_ptr->last_egress_send_time.store(right_now());
		break;
	default:
		return;
		break;
	}
}

void relay_mode::sequential_extract()
{
	listener_decryption_task_count--;
	std::unique_lock locker{ mutex_decryptions_from_listener };

	if (decryptions_from_listener.empty())
		return;

	for (auto iter = decryptions_from_listener.begin(), next = iter;
		iter != decryptions_from_listener.end();
		iter = next)
	{
		next++;
		auto& task_results = *iter;
		if (task_results.wait_for(std::chrono::seconds(0)) != std::future_status::ready)
			break;
		auto [error_message, data, plain_size, peer, port_number] = task_results.get();
		if (error_message.empty() && plain_size > 0)
		{
			udp_listener_incoming_unpack(std::move(data), plain_size, peer, port_number);
		}
		decryptions_from_listener.erase(iter);
	}

	if (decryptions_from_listener.empty())
		return;
	locker.unlock();

	if (listener_decryption_task_count.load() > 0)
		return;
	listener_decryption_task_count++;
	sequence_task_pool.push_task(std::this_thread::get_id(),
		[this](std::unique_ptr<uint8_t[]>) { sequential_extract(); }, std::unique_ptr<uint8_t[]>{});
}

void relay_mode::udp_listener_incoming_new_connection(std::unique_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint &peer, udp_server *listener_ptr)
{
	if (data_size == 0)
		return;

	uint8_t *data_ptr = data.get();

	uint32_t iden = packet::data_wrapper::extract_iden(data_ptr);
	std::shared_ptr<udp_mappings> udp_session_ptr = std::make_shared<udp_mappings>();
	udp_session_ptr->wrapper_ptr = std::make_unique<packet::data_wrapper>(iden, udp_session_ptr);
	udp_session_ptr->hopping_wrapper_ptr = std::make_unique<packet::data_wrapper>(0, udp_session_ptr);
	packet::data_wrapper *data_wrapper_ptr = udp_session_ptr->wrapper_ptr.get();

	auto [packet_timestamp, feature_value, received_data, received_size] = data_wrapper_ptr->receive_data(data_ptr, data_size);
	if (received_size == 0)
		return;

	auto timestamp = right_now();
	if (calculate_difference<int64_t>((uint32_t)timestamp, packet_timestamp) > TIME_GAP)
		return;

	udp_session_ptr->ingress_source_endpoint = std::make_shared<udp::endpoint>(peer);
	udp_session_ptr->ingress_sender.store(listener_ptr);

	switch (feature_value)
	{
	case feature::keep_alive:
		if (current_settings.fec_data == 0 || current_settings.fec_redundant == 0)
		{
			auto [response_packet, response_packet_size] = udp_session_ptr->wrapper_ptr->create_keep_alive_response_packet();
			data_sender_via_listener(udp_session_ptr, peer, std::move(response_packet), response_packet_size);
		}
		else
		{
			auto [response_packet, response_packet_size] = udp_session_ptr->wrapper_ptr->create_random_small_packet();
			fec_maker_via_listener(udp_session_ptr, feature::keep_alive_response, std::move(response_packet), response_packet_size);
		}
		return;
		break;
	case feature::test_connection:
		return;
		break;
	case feature::keep_alive_response:
		return;
		break;
	case feature::raw_data:
		break;
	default:
		return;
		break;
	}

	std::shared_ptr<forwarder> udp_forwarder = nullptr;
	try
	{
		auto bind_push_func = std::bind(&ttp::task_group_pool::push_task_forwarder, &sequence_task_pool, _1, _2, _3);
		auto bind_check_limit_func = [this](size_t number) -> bool {return sequence_task_pool.get_forwarder_network_task_count(number) > TASK_COUNT_LIMIT; };
		auto udp_func = std::bind(&relay_mode::udp_forwarder_incoming_to_udp, this, _1, _2, _3, _4, _5);
		udp_forwarder = std::make_shared<forwarder>(io_context, bind_push_func, bind_check_limit_func, udp_session_ptr, udp_func, current_settings.egress->ip_version_only);
		if (udp_forwarder == nullptr)
			return;
	}
	catch (std::exception &ex)
	{
		std::string error_message = time_to_string_with_square_brackets() + "Cannot create new connection, error: " + ex.what() + "\n";
		std::cerr << error_message;
		print_message_to_file(error_message, current_settings.log_messages);
	}

	size_t selected_index = randomly_pick_index(current_settings.destination_address_list.size());
	std::shared_ptr<udp::endpoint> egress_target_endpoint = get_udp_target(udp_forwarder, selected_index);
	if (egress_target_endpoint == nullptr)
		return;
	udp_session_ptr->egress_target_endpoint = egress_target_endpoint;
	udp_session_ptr->hopping_timestamp.store(right_now() + current_settings.egress->dynamic_port_refresh);
	udp_session_ptr->hopping_available.store(hop_status::pending);
	udp_session_ptr->hopping_endpoint = std::make_shared<udp::endpoint>();
	udp_session_ptr->egress_forwarder = udp_forwarder;
	udp_session_ptr->egress_previous_target_endpoint = std::make_shared<udp::endpoint>(*egress_target_endpoint);
	udp_session_ptr->egress_endpoint_index = selected_index;

	std::unique_ptr<uint8_t[]> new_data = std::make_unique<uint8_t[]>(received_size + BUFFER_EXPAND_SIZE);
	uint8_t *packing_data_ptr = new_data.get();
	std::copy(received_data, received_data + received_size, packing_data_ptr);
	size_t packed_data_size = data_wrapper_ptr->pack_data(feature::raw_data, packing_data_ptr, received_size);
	auto [error_message, cipher_size] = encrypt_data(current_settings.egress->encryption_password, current_settings.egress->encryption, packing_data_ptr, (int)packed_data_size);
	if (!error_message.empty() || cipher_size == 0)
		return;

	asio::error_code ec;
	udp_forwarder->send_out(packing_data_ptr, cipher_size, *egress_target_endpoint, ec);
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

	udp_session_channels[iden] = udp_session_ptr;
}

void relay_mode::udp_listener_response_test_connection(std::unique_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint &peer, udp_server *listener_ptr)
{
	if (data_size == 0)
		return;

	uint8_t *data_ptr = data.get();
	std::shared_ptr<udp_mappings> udp_session_ptr = udp_zero_sessions[listener_ptr];
	packet::data_wrapper *data_wrapper_ptr = udp_session_ptr->wrapper_ptr.get();

	auto [packet_timestamp, feature_value, received_data, received_size] = data_wrapper_ptr->receive_data(data_ptr, data_size);
	if (received_size == 0 || feature_value != feature::test_connection)
		return;

	auto timestamp = right_now();
	if (calculate_difference<int64_t>((uint32_t)timestamp, packet_timestamp) > TIME_GAP)
		return;

	udp_session_ptr->ingress_source_endpoint = std::make_shared<udp::endpoint>(peer);

	if (current_settings.fec_data > 0 && current_settings.fec_redundant > 0)
	{
		auto [packet_header, fec_data_ptr, fec_data_size] = udp_session_ptr->wrapper_ptr->receive_data_with_fec(data_ptr, data_size);
		if (packet_header.sub_sn >= current_settings.fec_data)
			return;

		received_data = fec_data_ptr;
		received_size = fec_data_size;
	}

	uint32_t test_iden = data_wrapper_ptr->unpack_test_iden(received_data);

	if (current_settings.fec_data == 0 || current_settings.fec_redundant == 0)
	{
		auto [response_packet, response_packet_size] = udp_session_ptr->wrapper_ptr->create_test_connection_packet(test_iden);
		data_sender_via_listener(udp_session_ptr, peer, std::move(response_packet), response_packet_size);
	}
	else
	{
		auto [response_packet, response_packet_size] = udp_session_ptr->wrapper_ptr->create_small_packet(test_iden);
		size_t fec_data_buffer_size = udp_session_ptr->wrapper_ptr->pack_data_with_fec(feature_value, response_packet.get(), response_packet_size, 0, 0);
		data_sender_via_listener(udp_session_ptr, peer, std::move(response_packet), fec_data_buffer_size);
	}
}

void relay_mode::udp_forwarder_incoming_to_udp(std::weak_ptr<udp_mappings> udp_session_weak_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint &peer, asio::ip::port_type local_port_number)
{
	std::shared_ptr<udp_mappings> udp_session_ptr = udp_session_weak_ptr.lock();
	if (data_size == 0 || udp_session_ptr == nullptr || data == nullptr)
		return;

	if (data_size < RAW_HEADER_SIZE)
		return;

	if (forwarder_parallels != nullptr)
	{
		parallel_decrypt_via_forwarder(udp_session_ptr, std::move(data), data_size, peer, local_port_number);
		return;
	}

	uint8_t *data_ptr = data.get();
	auto [error_message, plain_size] = decrypt_data(current_settings.encryption_password, current_settings.encryption, data_ptr, (int)data_size);
	if (!error_message.empty() || plain_size == 0)
		return;

	udp_forwarder_incoming_to_udp_unpack(udp_session_ptr, std::move(data), plain_size, peer, local_port_number);
}

void relay_mode::udp_forwarder_incoming_to_udp_unpack(std::shared_ptr<udp_mappings> udp_session_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint &peer, asio::ip::port_type local_port_number)
{
	if (data_size == 0 || udp_session_ptr == nullptr)
		return;

	uint8_t *data_ptr = data.get();

	uint32_t iden = udp_session_ptr->wrapper_ptr->extract_iden(data_ptr);
	if (iden == 0)
	{
		if (udp_session_ptr->hopping_available.load() == hop_status::testing)
			verify_testing_response(udp_session_ptr, std::move(data), data_size);
		return;
	}

	if (udp_session_ptr->wrapper_ptr->get_iden() != iden)
	{
		return;
	}

	auto [packet_timestamp, feature_value, received_data_ptr, received_size] = udp_session_ptr->wrapper_ptr->receive_data(data_ptr, data_size);
	if (received_size == 0 || packet_timestamp == 0 || feature_value == feature::test_connection)
		return;

	auto timestamp = right_now();
	if (calculate_difference<int64_t>((uint32_t)timestamp, packet_timestamp) > TIME_GAP)
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

	std::shared_ptr<udp::endpoint> egress_target_endpoint = std::atomic_load(&(udp_session_ptr->egress_target_endpoint));
	std::shared_ptr<udp::endpoint> egress_previous_target_endpoint = std::atomic_load(&(udp_session_ptr->egress_previous_target_endpoint));
	if (*egress_target_endpoint != peer && *egress_previous_target_endpoint != peer)
	{
		std::atomic_store(&(udp_session_ptr->egress_previous_target_endpoint), egress_target_endpoint);
		std::atomic_store(&(udp_session_ptr->egress_target_endpoint), std::make_shared<udp::endpoint>(peer));
		std::atomic_store(&target_address[udp_session_ptr->egress_endpoint_index], std::make_shared<asio::ip::address>(peer.address()));
	}

	switch (feature_value)
	{
	case feature::keep_alive:
		if (current_settings.fec_data == 0 || current_settings.fec_redundant == 0)
		{
			auto [response_packet, response_packet_size] = udp_session_ptr->wrapper_ptr->create_keep_alive_response_packet();
			data_sender_via_forwarder(udp_session_ptr, std::move(response_packet), response_packet_size);
		}
		else
		{
			auto [response_packet, response_packet_size] = udp_session_ptr->wrapper_ptr->create_random_small_packet();
			fec_maker_via_forwarder(udp_session_ptr, feature::keep_alive_response, std::move(response_packet), response_packet_size);
		}
		break;
	case feature::test_connection:
		break;
	case feature::keep_alive_response:
		break;
	case feature::raw_data:
	{
		std::unique_ptr<uint8_t[]> new_data = std::make_unique<uint8_t[]>(received_size + BUFFER_EXPAND_SIZE);
		if (current_settings.ingress->fec_data == 0 || current_settings.ingress->fec_redundant == 0)
		{
			size_t packed_data_size = udp_session_ptr->wrapper_ptr->pack_data(feature::raw_data, new_data.get(), received_size);
			std::shared_ptr<udp::endpoint> ingress_source_endpoint = std::atomic_load(&(udp_session_ptr->ingress_source_endpoint));
			data_sender_via_listener(udp_session_ptr, *ingress_source_endpoint, std::move(new_data), packed_data_size);
		}
		else
		{
			fec_maker_via_listener(udp_session_ptr, feature::raw_data, std::move(new_data), received_size);
		}

		udp_session_ptr->last_egress_receive_time.store(right_now());
		udp_session_ptr->last_inress_send_time.store(right_now());

		break;
	}
	default:
		break;
	}
}

void relay_mode::udp_forwarder_incoming_to_udp_unpack(std::shared_ptr<udp_mappings> udp_session_ptr)
{
	if (udp_session_ptr == nullptr)
		return;

	udp_session_ptr->forwarder_decryption_task_count--;
	std::unique_lock locker{ udp_session_ptr->mutex_decryptions_from_forwarder };	
	if (udp_session_ptr->decryptions_from_forwarder.empty())
		return;

	for (auto iter = udp_session_ptr->decryptions_from_forwarder.begin(), next = iter;
		iter != udp_session_ptr->decryptions_from_forwarder.end();
		iter = next)
	{
		next++;
		auto& task_results = *iter;
		if (task_results.wait_for(std::chrono::seconds(0)) != std::future_status::ready)
			break;
		auto [error_message, data, plain_size, peer, local_port_number] = task_results.get();
		if (error_message.empty() && plain_size > 0)
		{
			udp_forwarder_incoming_to_udp_unpack(udp_session_ptr, std::move(data), plain_size, peer, local_port_number);
		}
		udp_session_ptr->decryptions_from_forwarder.erase(iter);
	}

	if (udp_session_ptr->decryptions_from_forwarder.empty())
		return;

	locker.unlock();
	if (udp_session_ptr->forwarder_decryption_task_count.load() > 0)
		return;
	udp_session_ptr->forwarder_decryption_task_count++;
	std::weak_ptr<udp_mappings> udp_session_ptr_weak = udp_session_ptr;
	sequence_task_pool.push_task_listener((size_t)udp_session_ptr.get(),
		[this, udp_session_ptr_weak](std::unique_ptr<uint8_t[]>) { udp_forwarder_incoming_to_udp_unpack(udp_session_ptr_weak.lock()); },
		std::unique_ptr<uint8_t[]>{});
}

std::unique_ptr<udp::endpoint> relay_mode::get_udp_target(std::shared_ptr<forwarder> target_connector, size_t index)
{
	std::shared_ptr<asio::ip::address> target = std::atomic_load(&target_address[index]);
	if (target != nullptr)
	{
		uint16_t destination_port = current_settings.destination_ports.front();
		if (current_settings.destination_ports.size() > 0)
			destination_port = generate_new_port_number(current_settings.destination_ports);

		return std::make_unique<udp::endpoint>(*target, destination_port);
	}

	return update_udp_target(target_connector, index);
}

std::unique_ptr<udp::endpoint> relay_mode::update_udp_target(std::shared_ptr<forwarder> target_connector, size_t index)
{
	uint16_t destination_port = current_settings.destination_ports.front();
	if (current_settings.destination_ports.size() > 0)
		destination_port = generate_new_port_number(current_settings.destination_ports);

	std::unique_ptr<udp::endpoint> udp_target;
	asio::error_code ec;
	for (int i = 0; i <= RETRY_TIMES; ++i)
	{
		const std::string &destination_address = current_settings.destination_address_list[index];
		udp::resolver::results_type udp_endpoints = target_connector->get_remote_hostname(destination_address, 0, ec);
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
			udp_target = std::make_unique<udp::endpoint>(*udp_endpoints.begin());
			udp_target->port(destination_port);
			std::atomic_store(&target_address[index], std::make_shared<asio::ip::address>(udp_target->address()));
			break;
		}
	}

	return std::move(udp_target);
}

void relay_mode::save_external_ip_address(uint32_t ipv4_address, uint16_t ipv4_port, const std::array<uint8_t, 16> &ipv6_address, uint16_t ipv6_port)
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

void relay_mode::data_sender_via_listener(std::shared_ptr<udp_mappings> udp_session_ptr, const udp::endpoint &peer, std::unique_ptr<uint8_t[]> data, size_t data_size)
{
	if (listener_parallels != nullptr)
	{
		parallel_encrypt_via_listener(udp_session_ptr, std::unique_ptr<udp::endpoint>{}, std::move(data), data_size);
		return;
	}

	auto [error_message, cipher_size] = encrypt_data(current_settings.ingress->encryption_password, current_settings.ingress->encryption, data.get(), (int)data_size);
	if (error_message.empty() && cipher_size > 0)
		udp_session_ptr->ingress_sender.load()->async_send_out(std::move(data), cipher_size, peer);
}

void relay_mode::data_sender_via_listener(std::shared_ptr<udp_mappings> udp_session_ptr)
{
	if (udp_session_ptr == nullptr)
		return;
	udp_session_ptr->listener_encryption_task_count--;
	std::unique_lock locker{ udp_session_ptr->mutex_encryptions_via_listener };
	if (udp_session_ptr->encryptions_via_listener.empty())
		return;

	for (auto iter = udp_session_ptr->encryptions_via_listener.begin(), next = iter;
		iter != udp_session_ptr->encryptions_via_listener.end();
		iter = next)
	{
		next++;
		auto &task_results = *iter;
		if (task_results.wait_for(std::chrono::seconds(0)) != std::future_status::ready)
			break;
		auto [error_message, data, cipher_size, udp_endpoint_ptr] = task_results.get();
		if (error_message.empty() && cipher_size > 0 && udp_endpoint_ptr != nullptr)
			udp_session_ptr->ingress_sender.load()->async_send_out(std::move(data), cipher_size, *udp_endpoint_ptr);
		udp_session_ptr->encryptions_via_listener.erase(iter);
	}

	if (udp_session_ptr->encryptions_via_listener.empty())
		return;
	locker.unlock();
	if (udp_session_ptr->listener_encryption_task_count.load() > 0)
		return;
	std::weak_ptr<udp_mappings> udp_session_ptr_weak = udp_session_ptr;
	udp_session_ptr->listener_encryption_task_count++;
	sequence_task_pool.push_task_listener((size_t)udp_session_ptr.get(),
		[this, udp_session_ptr_weak](std::unique_ptr<uint8_t[]>) { data_sender_via_listener(udp_session_ptr_weak.lock()); },
		std::unique_ptr<uint8_t[]>{});
}

void relay_mode::parallel_encrypt_via_listener(std::shared_ptr<udp_mappings> udp_session_ptr, std::shared_ptr<udp::endpoint> peer, std::unique_ptr<uint8_t[]> data, size_t data_size)
{
	std::function<udp_mappings::encryption_result(std::unique_ptr<uint8_t[]>)> func =
		[this, peer, data_size](std::unique_ptr<uint8_t[]> data) mutable
		-> udp_mappings::encryption_result
		{
			auto [error_message, cipher_size] = encrypt_data(current_settings.encryption_password, current_settings.encryption, data.get(), (int)data_size);
			return { error_message, std::move(data), cipher_size, peer };
		};

	auto task_future = listener_parallels->submit(func, std::move(data));
	std::unique_lock locker{ udp_session_ptr->mutex_encryptions_via_listener };
	udp_session_ptr->encryptions_via_listener.emplace_back(std::move(task_future));
	locker.unlock();
	udp_session_ptr->listener_encryption_task_count++;
	data_sender_via_listener(udp_session_ptr);
}

void relay_mode::parallel_decrypt_via_listener(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, udp_server *listener_ptr)
{
	std::function<udp_mappings::decryption_result_listener(std::unique_ptr<uint8_t[]>)> func =
		[this, data_size, peer, listener_ptr](std::unique_ptr<uint8_t[]> data) mutable
		-> udp_mappings::decryption_result_listener
		{
			uint8_t *data_ptr = data.get();
			auto [error_message, plain_size] = decrypt_data(current_settings.encryption_password, current_settings.encryption, data_ptr, (int)data_size);
			return { error_message, std::move(data), plain_size, peer, listener_ptr };
		};

	auto task_future = listener_parallels->submit(func, std::move(data));
	std::unique_lock locker{ mutex_decryptions_from_listener };
	decryptions_from_listener.emplace_back(std::move(task_future));
	locker.unlock();
	listener_decryption_task_count++;
	sequential_extract();
}

void relay_mode::data_sender_via_forwarder(std::shared_ptr<udp_mappings> udp_session_ptr, const udp::endpoint &peer, std::unique_ptr<uint8_t[]> data, size_t data_size)
{
	auto [error_message, cipher_size] = encrypt_data(current_settings.egress->encryption_password, current_settings.egress->encryption, data.get(), (int)data_size);
	if (error_message.empty() && cipher_size > 0)
	{
		std::shared_ptr<forwarder> egress_forwarder = std::atomic_load(&udp_session_ptr->egress_forwarder);
		egress_forwarder->async_send_out(std::move(data), cipher_size, peer);
	}
	change_new_port(udp_session_ptr);
}

void relay_mode::data_sender_via_forwarder(std::shared_ptr<udp_mappings> udp_session_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size)
{
	auto [error_message, cipher_size] = encrypt_data(current_settings.egress->encryption_password, current_settings.egress->encryption, data.get(), (int)data_size);
	if (error_message.empty() && cipher_size > 0)
	{
		std::shared_ptr<forwarder> egress_forwarder = std::atomic_load(&udp_session_ptr->egress_forwarder);
		std::shared_ptr<udp::endpoint> egress_target_endpoint = std::atomic_load(&udp_session_ptr->egress_target_endpoint);
		egress_forwarder->async_send_out(std::move(data), cipher_size, *egress_target_endpoint);
	}
	change_new_port(udp_session_ptr);
}

void relay_mode::data_sender_via_forwarder(std::shared_ptr<udp_mappings> udp_session_ptr)
{
	if (udp_session_ptr == nullptr)
		return;
	std::unique_lock locker{ udp_session_ptr->mutex_encryptions_via_forwarder };
	if (udp_session_ptr->encryptions_via_forwarder.empty())
		return;

	for (auto iter = udp_session_ptr->encryptions_via_forwarder.begin(), next = iter;
		iter != udp_session_ptr->encryptions_via_forwarder.end();
		iter = next)
	{
		next++;
		auto &task_results = *iter;
		if (task_results.wait_for(std::chrono::seconds(0)) != std::future_status::ready)
			break;
		auto [error_message, data, cipher_size, udp_endpoint_ptr] = task_results.get();
		if (error_message.empty() && cipher_size > 0)
		{
			std::shared_ptr<forwarder> egress_forwarder = std::atomic_load(&udp_session_ptr->egress_forwarder);
			std::shared_ptr<udp::endpoint> egress_target_endpoint =
				udp_endpoint_ptr == nullptr ? std::atomic_load(&udp_session_ptr->egress_target_endpoint) : std::move(udp_endpoint_ptr);
			egress_forwarder->async_send_out(std::move(data), cipher_size, *egress_target_endpoint);
		}
		udp_session_ptr->encryptions_via_forwarder.erase(iter);
	}

	bool is_empty = udp_session_ptr->encryptions_via_forwarder.empty();
	locker.unlock();
	change_new_port(udp_session_ptr);

	if (is_empty) return;

	std::weak_ptr<udp_mappings> udp_session_ptr_weak = udp_session_ptr;
	sequence_task_pool.push_task_forwarder((size_t)udp_session_ptr.get(),
		[this, udp_session_ptr_weak](std::unique_ptr<uint8_t[]>) { data_sender_via_forwarder(udp_session_ptr_weak.lock()); },
		std::unique_ptr<uint8_t[]>{});
}

void relay_mode::parallel_encrypt_via_forwarder(std::shared_ptr<udp_mappings> udp_session_ptr, std::shared_ptr<udp::endpoint> peer, std::unique_ptr<uint8_t[]> data, size_t data_size)
{
	std::function<udp_mappings::encryption_result(std::unique_ptr<uint8_t[]>)> func =
		[this, peer, data_size](std::unique_ptr<uint8_t[]> data) mutable
		-> udp_mappings::encryption_result
		{
			auto [error_message, cipher_size] = encrypt_data(current_settings.encryption_password, current_settings.encryption, data.get(), (int)data_size);
			return { error_message, std::move(data), cipher_size, peer };
		};

	auto task_future = forwarder_parallels->submit(func, std::move(data));
	std::unique_lock locker{ udp_session_ptr->mutex_encryptions_via_forwarder };
	udp_session_ptr->encryptions_via_forwarder.emplace_back(std::move(task_future));
	locker.unlock();
	data_sender_via_forwarder(udp_session_ptr);
}

void relay_mode::parallel_decrypt_via_forwarder(std::shared_ptr<udp_mappings> udp_session_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type local_port_number)
{
	std::function<udp_mappings::decryption_result_forwarder(std::unique_ptr<uint8_t[]>)> func =
		[this, data_size, peer, local_port_number](std::unique_ptr<uint8_t[]> data) mutable
		-> udp_mappings::decryption_result_forwarder
		{
			uint8_t* data_ptr = data.get();
			auto [error_message, plain_size] = decrypt_data(current_settings.encryption_password, current_settings.encryption, data_ptr, (int)data_size);
			return { error_message, std::move(data), plain_size, peer, local_port_number };
		};

	auto task_future = forwarder_parallels->submit(func, std::move(data));
	std::unique_lock locker{ udp_session_ptr->mutex_decryptions_from_forwarder };
	udp_session_ptr->decryptions_from_forwarder.emplace_back(std::move(task_future));
	locker.unlock();
	udp_session_ptr->forwarder_decryption_task_count++;
	udp_forwarder_incoming_to_udp_unpack(udp_session_ptr);
}

void relay_mode::fec_maker_via_listener(std::shared_ptr<udp_mappings> udp_session_ptr, feature feature_value, std::unique_ptr<uint8_t[]> data, size_t data_size)
{
	fec_control_data &fec_controllor = udp_session_ptr->fec_ingress_control;

	fec_controllor.fec_snd_cache.emplace_back(clone_into_pair(data.get(), data_size));

	size_t fec_data_buffer_size = udp_session_ptr->wrapper_ptr->pack_data_with_fec(feature_value, data.get(), data_size, fec_controllor.fec_snd_sn.load(), fec_controllor.fec_snd_sub_sn++);
	std::shared_ptr<udp::endpoint> ingress_source_endpoint = std::atomic_load(&(udp_session_ptr->ingress_source_endpoint));
	data_sender_via_listener(udp_session_ptr, *ingress_source_endpoint, std::move(data), fec_data_buffer_size);

	if (fec_controllor.fec_snd_cache.size() == current_settings.ingress->fec_data)
	{
		auto [array_data, fec_align_length, total_size] = compact_into_container(fec_controllor.fec_snd_cache);
		auto redundants = fec_controllor.fecc.encode(array_data.get(), total_size, fec_align_length);
		for (auto &data_ptr : redundants)
		{
			auto [fec_redundant_buffer, fec_redundant_buffer_size] = udp_session_ptr->wrapper_ptr->pack_data_with_fec(
				feature_value,
				(const uint8_t *)data_ptr.get(), fec_align_length,
				fec_controllor.fec_snd_sn.load(), fec_controllor.fec_snd_sub_sn++);
			data_sender_via_listener(udp_session_ptr, *ingress_source_endpoint, std::move(fec_redundant_buffer), fec_redundant_buffer_size);
		}
		fec_controllor.fec_snd_cache.clear();
		fec_controllor.fec_snd_sub_sn.store(0);
		fec_controllor.fec_snd_sn++;
	}
}

void relay_mode::fec_maker_via_forwarder(std::shared_ptr<udp_mappings> udp_session_ptr, feature feature_value, std::unique_ptr<uint8_t[]> data, size_t data_size)
{
	fec_control_data &fec_controllor = udp_session_ptr->fec_egress_control;

	fec_controllor.fec_snd_cache.emplace_back(clone_into_pair(data.get(), data_size));

	size_t fec_data_buffer_size = udp_session_ptr->wrapper_ptr->pack_data_with_fec(feature_value, data.get(), data_size, fec_controllor.fec_snd_sn.load(), fec_controllor.fec_snd_sub_sn++);
	data_sender_via_forwarder(udp_session_ptr, std::move(data), fec_data_buffer_size);

	if (fec_controllor.fec_snd_cache.size() == current_settings.egress->fec_data)
	{
		auto [array_data, fec_align_length, total_size] = compact_into_container(fec_controllor.fec_snd_cache);
		auto redundants = fec_controllor.fecc.encode(array_data.get(), total_size, fec_align_length);
		for (auto &data_ptr : redundants)
		{
			auto [fec_redundant_buffer, fec_redundant_buffer_size] = udp_session_ptr->wrapper_ptr->pack_data_with_fec(
				feature_value,
				(const uint8_t *)data_ptr.get(), fec_align_length,
				fec_controllor.fec_snd_sn.load(), fec_controllor.fec_snd_sub_sn++);
			data_sender_via_forwarder(udp_session_ptr, std::move(fec_redundant_buffer), fec_redundant_buffer_size);
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
			std::shared_ptr<udp::endpoint> ingress_source_endpoint = std::atomic_load(&(udp_session_ptr->ingress_source_endpoint));
			data_sender_via_listener(udp_session_ptr, *ingress_source_endpoint, std::move(data), data_size);
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
		std::shared_ptr<forwarder> egress_forwarder = std::atomic_load(&udp_session_ptr->egress_forwarder);

		if (time_elapsed > CLEANUP_WAITS / 3 &&
			time_elapsed <= CLEANUP_WAITS * 2 / 3 &&
			egress_forwarder != nullptr)
			egress_forwarder->pause(true);

		if (time_elapsed > CLEANUP_WAITS * 2 / 3 &&
			egress_forwarder != nullptr)
			egress_forwarder->stop();

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

				std::shared_ptr<forwarder> egress_forwarder = std::atomic_load(&udp_session_ptr->egress_forwarder);
				old_forwarders.push_back(egress_forwarder);
				egress_forwarder->stop();
#if __GNUC__ == 12 && __GNUC_MINOR__ < 3
				udp_session_ptr->egress_forwarder.store(nullptr);
#else
				udp_session_ptr->egress_forwarder = nullptr;
#endif
				udp_session_channels.erase(iter);
				udp_session_ptr->hopping_timestamp.store(LLONG_MAX);
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

		if (current_settings.fec_data == 0 || current_settings.fec_redundant == 0)
		{
			auto [response_packet, response_packet_size] = udp_session_ptr->wrapper_ptr->create_keep_alive_response_packet();
			std::shared_ptr<udp::endpoint> ingress_source_endpoint = std::atomic_load(&(udp_session_ptr->ingress_source_endpoint));
			data_sender_via_listener(udp_session_ptr, *ingress_source_endpoint, std::move(response_packet), response_packet_size);
		}
		else
		{
			auto [response_packet, response_packet_size] = udp_session_ptr->wrapper_ptr->create_random_small_packet();
			fec_maker_via_listener(udp_session_ptr, feature::keep_alive_response, std::move(response_packet), response_packet_size);
		}

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

		if (current_settings.fec_data == 0 || current_settings.fec_redundant == 0)
		{
			auto [response_packet, response_packet_size] = udp_session_ptr->wrapper_ptr->create_keep_alive_response_packet();
			data_sender_via_forwarder(udp_session_ptr, std::move(response_packet), response_packet_size);
		}
		else
		{
			auto [response_packet, response_packet_size] = udp_session_ptr->wrapper_ptr->create_random_small_packet();
			fec_maker_via_forwarder(udp_session_ptr, feature::keep_alive_response, std::move(response_packet), response_packet_size);
		}

		udp_session_ptr->keep_alive_egress_timestamp += current_settings.egress->keep_alive;
	}
}

void relay_mode::loop_hopping_test()
{
	auto time_right_now = right_now();
	std::set<std::shared_ptr<udp_mappings>> remove_later;
	std::shared_lock locker_shared{ mutex_hopping_sessions };
	for (auto &[udp_session_ptr, start_time] : hopping_sessions)
	{
		if (calculate_difference(start_time, time_right_now) > RETRY_TIMES)
		{
			remove_later.insert(udp_session_ptr);
			continue;
		}

		uint32_t iden = udp_session_ptr->wrapper_ptr->get_iden();
		if (current_settings.fec_data == 0 || current_settings.fec_redundant == 0)
		{
			auto [response_packet, response_packet_size] = udp_session_ptr->hopping_wrapper_ptr->create_test_connection_packet();
			std::shared_ptr<udp::endpoint> hopping_endpoint = std::atomic_load(&(udp_session_ptr->hopping_endpoint));
			data_sender_via_forwarder(udp_session_ptr,*hopping_endpoint, std::move(response_packet), response_packet_size);
		}
		else
		{
			auto [response_packet, response_packet_size] = udp_session_ptr->hopping_wrapper_ptr->create_small_packet();
			size_t fec_data_buffer_size = udp_session_ptr->hopping_wrapper_ptr->pack_data_with_fec(feature::test_connection, response_packet.get(), response_packet_size, 0, 0);
			std::shared_ptr<udp::endpoint> hopping_endpoint = std::atomic_load(&(udp_session_ptr->hopping_endpoint));
			data_sender_via_forwarder(udp_session_ptr, *hopping_endpoint, std::move(response_packet), response_packet_size);
		}
	}
	locker_shared.unlock();

	if (remove_later.empty())
		return;

	std::unique_lock locker{ mutex_hopping_sessions };
	for (auto& udp_session_ptr : remove_later)
	{
		hopping_sessions.erase(udp_session_ptr);
#if __GNUC__ == 12 && __GNUC_MINOR__ < 3
		udp_session_ptr->egress_hopping_forwarder.store(nullptr);
#else
		udp_session_ptr->egress_hopping_forwarder = nullptr;
#endif
		udp_session_ptr->hopping_available.store(hop_status::pending);
		udp_session_ptr->hopping_timestamp.store(time_right_now);
	}
	locker.unlock();
}

void relay_mode::send_stun_request(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
		return;

	if (current_settings.ingress->stun_server.empty())
		return;

	resend_stun_8489_request(*udp_servers.front(), current_settings.ingress->stun_server, stun_header.get(), current_settings.ingress->ip_version_only);

	timer_stun.expires_after(STUN_RESEND);
	timer_stun.async_wait([this](const asio::error_code &e) { send_stun_request(e); });
}

void relay_mode::find_expires(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
	{
		return;
	}

	loop_timeout_sessions();
	loop_hopping_test();

	timer_find_timeout.expires_after(FINDER_TIMEOUT_INTERVAL);
	timer_find_timeout.async_wait([this](const asio::error_code &e) { find_expires(e); });
}

void relay_mode::expiring_wrapper_loops(const asio::error_code &e)
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
	if (udp_mappings_ptr->hopping_timestamp.load() > right_now())
		return;
	udp_mappings_ptr->hopping_timestamp.store(LLONG_MAX);

	switch (udp_mappings_ptr->hopping_available.load())
	{
	case hop_status::pending:
		test_before_change(udp_mappings_ptr);
		break;
	case hop_status::available:
		switch_new_port(udp_mappings_ptr);
		break;
	default:
		break;
	}
}

void relay_mode::test_before_change(std::shared_ptr<udp_mappings> udp_mappings_ptr)
{
	auto time_right_now = right_now();
	uint32_t iden = udp_mappings_ptr->wrapper_ptr->get_iden();
	const std::vector<uint16_t> &destination_ports = current_settings.destination_ports;
	const std::vector<std::string> &destination_address_list = current_settings.destination_address_list;
	asio::error_code ec;

	std::shared_ptr<forwarder> udp_forwarder = nullptr;
	try
	{
		auto bind_push_func = std::bind(&ttp::task_group_pool::push_task_forwarder, &sequence_task_pool, _1, _2, _3);
		auto bind_check_limit_func = [this](size_t number) -> bool {return sequence_task_pool.get_forwarder_network_task_count(number) > TASK_COUNT_LIMIT; };
		auto udp_func = std::bind(&relay_mode::udp_forwarder_incoming_to_udp, this, _1, _2, _3, _4, _5);
		udp_forwarder = std::make_shared<forwarder>(io_context, bind_push_func, bind_check_limit_func, udp_mappings_ptr, udp_func, current_settings.egress->ip_version_only);
		if (udp_forwarder == nullptr)
		{
			udp_mappings_ptr->hopping_timestamp.store(time_right_now + current_settings.dynamic_port_refresh);
			return;
		}
	}
	catch (std::exception &ex)
	{
		std::string error_message = time_to_string_with_square_brackets() + "Cannot switch to new port, error: " + ex.what() + "\n";
		std::cerr << error_message;
		print_message_to_file(error_message, current_settings.log_messages);
		udp_mappings_ptr->hopping_timestamp.store(time_right_now + current_settings.dynamic_port_refresh);
		return;
	}

	std::shared_ptr<udp::endpoint> egress_target_endpoint = std::atomic_load(&(udp_mappings_ptr->egress_target_endpoint));
	std::shared_ptr<udp::endpoint> hopping_endpoint;
	if (destination_address_list.size() > 1)
	{
		size_t selected_index = randomly_pick_index(destination_address_list.size());
		hopping_endpoint = get_udp_target(udp_forwarder, selected_index);
		udp_mappings_ptr->hopping_endpoint_index = hopping_endpoint == nullptr ? udp_mappings_ptr->egress_endpoint_index.load() : selected_index;
	}
	else if (destination_ports.size() > 1)
	{
		uint16_t current_port_number = egress_target_endpoint->port();
		uint16_t new_port_numer = generate_new_port_number(destination_ports);
		for (size_t retry_times = 0; new_port_numer == current_port_number && retry_times < RETRY_TIMES; retry_times++)
		{
			new_port_numer = generate_new_port_number(destination_ports);
		}
		hopping_endpoint = std::make_shared<udp::endpoint>(*egress_target_endpoint);
		hopping_endpoint->port(new_port_numer);
	}

	if (hopping_endpoint == nullptr)
		hopping_endpoint = std::make_shared<udp::endpoint>(*egress_target_endpoint);

	std::atomic_store(&(udp_mappings_ptr->hopping_endpoint), hopping_endpoint);

	std::shared_ptr<forwarder> new_forwarder = udp_forwarder;
	std::vector<uint8_t> keep_alive_packet = create_empty_data(current_settings.egress->encryption_password, current_settings.egress->encryption, EMPTY_PACKET_SIZE);
	udp_mappings_ptr->wrapper_ptr->write_iden(keep_alive_packet.data());

	if (current_settings.egress->ip_version_only == ip_only_options::ipv4)
		new_forwarder->send_out(std::move(keep_alive_packet), local_empty_target_v4, ec);
	else
		new_forwarder->send_out(std::move(keep_alive_packet), local_empty_target_v6, ec);

	if (ec)
	{
		udp_mappings_ptr->hopping_timestamp.store(time_right_now + current_settings.dynamic_port_refresh);
		return;
	}

	new_forwarder->async_receive();
	if (std::shared_ptr<forwarder> egress_hopping_forwarder = std::atomic_load(&(udp_mappings_ptr->egress_hopping_forwarder));
		egress_hopping_forwarder != nullptr)
	{
		egress_hopping_forwarder->pause(true);
		std::scoped_lock lock_expiring_forwarders{ mutex_expiring_forwarders };
		expiring_forwarders[egress_hopping_forwarder] = right_now();
	}
	std::atomic_store(&(udp_mappings_ptr->egress_hopping_forwarder), new_forwarder);

	udp_mappings_ptr->hopping_available.store(hop_status::testing);

	udp_mappings *udp_session_ptr = udp_mappings_ptr.get();
	udp_mappings_ptr->mapping_function = [udp_session_ptr]()
		{
			udp_session_ptr->hopping_available.store(hop_status::available);
			udp_session_ptr->hopping_timestamp.store(right_now());
		};

	std::unique_lock locker{ mutex_hopping_sessions };
	hopping_sessions[udp_mappings_ptr] = time_right_now;
	locker.unlock();
}

void relay_mode::switch_new_port(std::shared_ptr<udp_mappings> udp_mappings_ptr)
{
	udp_mappings_ptr->hopping_timestamp.store(right_now() + current_settings.dynamic_port_refresh);
	udp_mappings_ptr->hopping_available.store(hop_status::pending);

	std::shared_ptr<udp::endpoint> hopping_endpoint = std::atomic_load(&(udp_mappings_ptr->hopping_endpoint));
	std::atomic_store(&(udp_mappings_ptr->egress_previous_target_endpoint), std::atomic_load(&(udp_mappings_ptr->egress_target_endpoint)));
	std::atomic_store(&(udp_mappings_ptr->egress_target_endpoint), std::make_shared<udp::endpoint>(*hopping_endpoint));
	udp_mappings_ptr->egress_endpoint_index = udp_mappings_ptr->hopping_endpoint_index.load();

	std::shared_ptr<forwarder> new_forwarder = std::atomic_load(&(udp_mappings_ptr->egress_hopping_forwarder));
	std::shared_ptr<forwarder> old_forwarder = std::atomic_load(&(udp_mappings_ptr->egress_forwarder));
	std::atomic_store(&(udp_mappings_ptr->egress_forwarder), new_forwarder);
#if __GNUC__ == 12 && __GNUC_MINOR__ < 3
	udp_mappings_ptr->egress_hopping_forwarder.store(nullptr);
#else
	udp_mappings_ptr->egress_hopping_forwarder = nullptr;
#endif

	std::scoped_lock lock_expiring_forwarders{ mutex_expiring_forwarders };
	if (expiring_forwarders.find(old_forwarder) == expiring_forwarders.end())
		expiring_forwarders.insert({ old_forwarder, right_now() });
}

void relay_mode::verify_testing_response(std::shared_ptr<udp_mappings> udp_session_ptr, std::unique_ptr<uint8_t[]> data, size_t plain_size)
{
	uint8_t* data_ptr = data.get();
	auto [packet_timestamp, feature_value, received_data_ptr, received_size] = udp_session_ptr->hopping_wrapper_ptr->receive_data(data_ptr, plain_size);
	if (received_size == 0 || packet_timestamp == 0 || feature_value != feature::test_connection)
		return;

	auto timestamp = right_now();
	if (calculate_difference<int64_t>((uint32_t)timestamp, packet_timestamp) > TIME_GAP)
		return;

	if (current_settings.fec_data > 0 && current_settings.fec_redundant > 0)
	{
		auto [packet_header, fec_data_ptr, fec_data_size] = udp_session_ptr->hopping_wrapper_ptr->receive_data_with_fec(data.get(), plain_size);
		if (packet_header.sub_sn >= current_settings.fec_data)
			return;

		received_data_ptr = fec_data_ptr;
		received_size = fec_data_size;
	}

	uint32_t iden = udp_session_ptr->hopping_wrapper_ptr->unpack_test_iden(received_data_ptr);
	if (iden != udp_session_ptr->wrapper_ptr->get_iden())
		return;

	if (std::atomic_load(&(udp_session_ptr->egress_hopping_forwarder)) != nullptr &&
		udp_session_ptr->hopping_available.load() == hop_status::testing)
	{
		std::unique_lock locker{ mutex_hopping_sessions };
		hopping_sessions.erase(udp_session_ptr);
		locker.unlock();
		udp_session_ptr->mapping_function();
	}
}

void relay_mode::keep_alive_ingress(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
	{
		return;
	}

	loop_keep_alive_ingress();

	timer_keep_alive_ingress.expires_after(KEEP_ALIVE_UPDATE_INTERVAL);
	timer_keep_alive_ingress.async_wait([this](const asio::error_code &e) { keep_alive_ingress(e); });
}

void relay_mode::keep_alive_egress(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
	{
		return;
	}

	loop_keep_alive_egress();

	timer_keep_alive_egress.expires_after(KEEP_ALIVE_UPDATE_INTERVAL);
	timer_keep_alive_egress.async_wait([this](const asio::error_code &e) { keep_alive_egress(e); });
}

void relay_mode::log_status(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
		return;

	loop_get_status();

	timer_status_log.expires_after(LOGGING_GAP);
	timer_status_log.async_wait([this](const asio::error_code &e) { log_status(e); });
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

	target_address.resize(current_settings.destination_address_list.size());
	udp_server_callback_t func = std::bind(&relay_mode::udp_listener_incoming, this, _1, _2, _3, _4);
	const std::vector<uint16_t> &listen_ports = current_settings.ingress->listen_ports;

	std::vector<udp::endpoint> listen_on_ep;
	std::vector<std::string> listen_on;
	if (!current_settings.listen_on.empty() || !current_settings.ingress->listen_on.empty())
	{
		std::set<std::string> listen_address(current_settings.listen_on.begin(), current_settings.listen_on.end());
		listen_address.insert(current_settings.ingress->listen_on.begin(), current_settings.ingress->listen_on.end());
		std::copy(listen_address.begin(), listen_address.end(), std::back_inserter(listen_on));;
	}

	if (listen_on.empty())
	{
		asio::ip::udp udp_ip_version = current_settings.ingress->ip_version_only == ip_only_options::ipv4 ? udp::v4() : udp::v6();
		listen_on_ep.resize(listen_ports.size());
		for (size_t i = 0; i < listen_ports.size(); i++)
			listen_on_ep[i] = udp::endpoint(udp_ip_version, listen_ports[i]);
	}
	else
	{
		asio::error_code ec;
		size_t port_count = listen_ports.size();
		size_t listen_count = port_count * listen_on.size();
		listen_on_ep.resize(listen_count);
		for (size_t index_address = 0; index_address < listen_on.size(); index_address++)
		{
			asio::ip::address local_address = asio::ip::make_address(listen_on[index_address], ec);
			if (ec)
			{
				std::string error_message = time_to_string_with_square_brackets() + "Listen Address incorrect - " + listen_on[index_address] + "\n";
				std::cerr << error_message;
				print_message_to_file(error_message, current_settings.log_messages);
				return false;
			}

			for (size_t index_ports = 0; index_ports < port_count; index_ports++)
			{
				size_t index = index_address * port_count + index_ports;
				if (local_address.is_v4() && current_settings.ingress->ip_version_only == ip_only_options::not_set)
					listen_on_ep[index].address(asio::ip::make_address_v6(asio::ip::v4_mapped, local_address.to_v4()));
				else
					listen_on_ep[index].address(local_address);
				listen_on_ep[index].port(listen_ports[index_ports]);
			}
		}
	}

	bool running_well = true;
	for (udp::endpoint ep : listen_on_ep)
	{
		try
		{
			auto bind_push_func = std::bind(&ttp::task_group_pool::push_task_listener, &sequence_task_pool, _1, _2, _3);
			auto bind_check_limit_func = [this](size_t number) -> bool {return sequence_task_pool.get_listener_network_task_count(number) > TASK_COUNT_LIMIT; };
			udp_servers.emplace_back(std::make_unique<udp_server>(io_context, bind_push_func, bind_check_limit_func, ep, func));
		}
		catch (std::exception &ex)
		{
			std::stringstream ss;
			ss << ep;
			std::string error_message = time_to_string_with_square_brackets() + ex.what() + "\tAddress: " + ss.str() + "\n";
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
			stun_header = send_stun_8489_request(*udp_servers.front(), current_settings.ingress->stun_server, current_settings.ingress->ip_version_only);
			timer_stun.expires_after(std::chrono::seconds(1));
			timer_stun.async_wait([this](const asio::error_code &e) { send_stun_request(e); });
		}

		if (current_settings.ingress->keep_alive > 0)
		{
			timer_keep_alive_ingress.expires_after(KEEP_ALIVE_UPDATE_INTERVAL);
			timer_keep_alive_ingress.async_wait([this](const asio::error_code &e) { keep_alive_ingress(e); });
		}
		if (current_settings.egress->keep_alive > 0)
		{
			timer_keep_alive_egress.expires_after(KEEP_ALIVE_UPDATE_INTERVAL);
			timer_keep_alive_egress.async_wait([this](const asio::error_code &e) { keep_alive_egress(e); });
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

