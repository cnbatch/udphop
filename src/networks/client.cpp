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
	timer_status_log.cancel();
}

bool client_mode::start()
{
	std::cout << app_name << " is running in client mode\n";

	uint16_t port_number = current_settings.listen_port;
	if (port_number == 0)
		return false;

	udp::endpoint listen_on_ep;
	if (current_settings.ip_version_only == ip_only_options::ipv4)
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

		if (local_address.is_v4() && current_settings.ip_version_only == ip_only_options::not_set)
			listen_on_ep.address(asio::ip::make_address_v6(asio::ip::v4_mapped, local_address.to_v4()));
		else
			listen_on_ep.address(local_address);
	}


	try
	{
		udp_callback_t udp_func_ap = std::bind(&client_mode::udp_listener_incoming, this, _1, _2, _3, _4);
		auto bind_push_func = std::bind(&ttp::task_group_pool::push_task_local, &sequence_task_pool, _1, _2, _3);
		auto bind_check_limit_func = [this](size_t number) -> bool { return sequence_task_pool.get_local_network_task_count(number) > TASK_COUNT_LIMIT; };
		udp_access_point = std::make_unique<udp_server>(network_io, bind_push_func, bind_check_limit_func, listen_on_ep, udp_func_ap);

		timer_find_timeout.expires_after(FINDER_TIMEOUT_INTERVAL);
		timer_find_timeout.async_wait([this](const asio::error_code &e) { find_expires(e); });

		timer_expiring_sessions.expires_after(EXPRING_UPDATE_INTERVAL);
		timer_expiring_sessions.async_wait([this](const asio::error_code &e) { expiring_wrapper_loops(e); });

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
				udp_listener_incoming_new_connection(std::move(data), data_size, peer, port_number);
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

	if (current_settings.fec_data == 0 || current_settings.fec_redundant == 0)
	{
		size_t packed_data_size = udp_session->wrapper_ptr->pack_data(feature::raw_data, data.get(), data_size);
		data_sender(udp_session, std::move(data), packed_data_size);
	}
	else
	{
		fec_maker(udp_session, feature::raw_data, std::move(data), data_size);
	}

	udp_session->last_ingress_receive_time.store(right_now());
	udp_session->last_egress_send_time.store(right_now());
}

void client_mode::udp_listener_incoming_new_connection(std::unique_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint &peer, asio::ip::port_type port_number)
{
	const std::string &destination_address = current_settings.destination_address;
	uint16_t destination_port = current_settings.destination_port;
	if (destination_port == 0)
		destination_port = generate_new_port_number(current_settings.destination_port_start, current_settings.destination_port_end);

	uint32_t key_number = generate_token_number();

	std::shared_ptr<forwarder> udp_forwarder = nullptr;
	std::shared_ptr<udp_mappings> udp_session_ptr = std::make_shared<udp_mappings>();
	try
	{
		auto bind_push_func = std::bind(&ttp::task_group_pool::push_task_peer, &sequence_task_pool, _1, _2, _3);
		auto bind_check_limit_func = [this](size_t number) -> bool {return sequence_task_pool.get_peer_network_task_count(number) > TASK_COUNT_LIMIT; };
		auto udp_func = std::bind(&client_mode::udp_forwarder_incoming_to_udp, this, _1, _2, _3, _4, _5);
		udp_forwarder = std::make_shared<forwarder>(io_context, bind_push_func, bind_check_limit_func, udp_session_ptr, udp_func, current_settings.ip_version_only);
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

	udp_session_ptr->wrapper_ptr = std::make_unique<packet::data_wrapper>(key_number, udp_session_ptr);
	udp_session_ptr->hopping_timestamp.store(right_now() + current_settings.dynamic_port_refresh);
	udp_session_ptr->hopping_available.store(hop_status::pending);
	udp_session_ptr->hopping_wrapper_ptr = std::make_unique<packet::data_wrapper>(0, udp_session_ptr);
	udp_session_ptr->egress_forwarder = udp_forwarder;
	udp_session_ptr->egress_previous_target_endpoint = udp_session_ptr->egress_target_endpoint;
	udp_session_ptr->ingress_source_endpoint = std::make_shared<udp::endpoint>(peer);
	packet::data_wrapper *data_wrapper_ptr = udp_session_ptr->wrapper_ptr.get();

	uint8_t *packing_data_ptr = data.get();
	size_t packed_data_size = data_wrapper_ptr->pack_data(feature::raw_data, packing_data_ptr, data_size);
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

	if (current_settings.fec_data > 0 && current_settings.fec_redundant > 0)
	{
		size_t K = current_settings.fec_data;
		size_t N = K + current_settings.fec_redundant;
		udp_session_ptr->fec_egress_control.fecc.reset_martix(K, N);
	}

	udp_session_ptr->last_ingress_receive_time.store(right_now());
	udp_session_ptr->last_egress_send_time.store(right_now());
}

void client_mode::udp_forwarder_incoming_to_udp(std::weak_ptr<udp_mappings> udp_session_weak_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type local_port_number)
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

	udp_forwarder_incoming_to_udp_unpack(udp_session_ptr, std::move(data), plain_size, peer, local_port_number);
}

void client_mode::udp_forwarder_incoming_to_udp_unpack(std::shared_ptr<udp_mappings> udp_session_ptr, std::unique_ptr<uint8_t[]> data, size_t plain_size, udp::endpoint peer, asio::ip::port_type local_port_number)
{
	if (plain_size == 0 || udp_session_ptr == nullptr)
		return;

	uint8_t *data_ptr = data.get();

	uint32_t iden = udp_session_ptr->wrapper_ptr->extract_iden(data_ptr);
	if (iden == 0)
	{
		if (udp_session_ptr->hopping_available.load() == hop_status::testing)
			verify_testing_response(udp_session_ptr, std::move(data), plain_size);
		return;
	}

	if (udp_session_ptr->wrapper_ptr->get_iden() != iden)
	{
		return;
	}

	auto [packet_timestamp, feature_value, received_data_ptr, received_size] = udp_session_ptr->wrapper_ptr->receive_data(data_ptr, plain_size);
	if (received_size == 0 || packet_timestamp == 0 || feature_value == feature::test_connection)
		return;

	auto timestamp = right_now();
	if (calculate_difference<int64_t>((uint32_t)timestamp, packet_timestamp) > TIME_GAP)
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
			udp_session_ptr->fec_egress_control.fec_rcv_cache[fec_sn][fec_sub_sn] = std::move(original_data);
			fec_find_missings(udp_session_ptr.get(), udp_session_ptr->fec_egress_control, fec_sn, current_settings.fec_data);
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
			fec_find_missings(udp_session_ptr.get(), udp_session_ptr->fec_egress_control, fec_sn, current_settings.fec_data);
		}
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

	switch (feature_value)
	{
	case feature::keep_alive:
		if (current_settings.fec_data == 0 || current_settings.fec_redundant == 0)
		{
			auto [response_packet, response_packet_size] = udp_session_ptr->wrapper_ptr->create_keep_alive_response_packet();
			data_sender(udp_session_ptr, std::move(response_packet), response_packet_size);
		}
		else
		{
			auto [response_packet, response_packet_size] = udp_session_ptr->wrapper_ptr->create_random_small_packet();
			fec_maker(udp_session_ptr, feature::keep_alive_response, std::move(response_packet), response_packet_size);
		}
		break;
	case feature::keep_alive_response:
		break;
	case feature::test_connection:
		break;
	case feature::raw_data:
	{
		std::shared_ptr<udp::endpoint> ingress_source_endpoint = udp_session_ptr->ingress_source_endpoint;
		udp_access_point->async_send_out(std::move(data), received_data_ptr, received_size, *ingress_source_endpoint);
		udp_session_ptr->last_egress_receive_time.store(right_now());
		udp_session_ptr->last_inress_send_time.store(right_now());
		break;
	}
	default:
		return;
		break;
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

void client_mode::data_sender(std::shared_ptr<udp_mappings> udp_session_ptr, const udp::endpoint &peer, std::unique_ptr<uint8_t[]> data, size_t data_size)
{
	auto [error_message, cipher_size] = encrypt_data(current_settings.encryption_password, current_settings.encryption, data.get(), (int)data_size);
	if (error_message.empty() && cipher_size > 0)
		udp_session_ptr->egress_forwarder->async_send_out(std::move(data), cipher_size, peer);
	change_new_port(udp_session_ptr);
}

void client_mode::data_sender(std::shared_ptr<udp_mappings> udp_session_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size)
{
	thread_local udp::endpoint debug_endpoint = {};
	auto [error_message, cipher_size] = encrypt_data(current_settings.encryption_password, current_settings.encryption, data.get(), (int)data_size);
	if (error_message.empty() && cipher_size > 0)
		udp_session_ptr->egress_forwarder->async_send_out(std::move(data), cipher_size, udp_session_ptr->egress_target_endpoint);
	if (udp_session_ptr->egress_target_endpoint != debug_endpoint)
		debug_endpoint = udp_session_ptr->egress_target_endpoint;
	change_new_port(udp_session_ptr);
}

void client_mode::data_sender(std::shared_ptr<udp_mappings> udp_session_ptr, std::vector<uint8_t> &&data)
{
	thread_local udp::endpoint debug_endpoint = {};
	std::string error_message;
	std::vector<uint8_t> encrypted_data = encrypt_data(current_settings.encryption_password, current_settings.encryption, std::move(data), error_message);
	if (error_message.empty() && encrypted_data.size() > 0)
		udp_session_ptr->egress_forwarder->async_send_out(std::move(encrypted_data), udp_session_ptr->egress_target_endpoint);
	if (udp_session_ptr->egress_target_endpoint != debug_endpoint)
		debug_endpoint = udp_session_ptr->egress_target_endpoint;
	change_new_port(udp_session_ptr);
}

void client_mode::fec_maker(std::shared_ptr<udp_mappings> udp_session_ptr, feature feature_value, std::unique_ptr<uint8_t[]> data, size_t data_size)
{
	fec_control_data &fec_controllor = udp_session_ptr->fec_egress_control;
	
	fec_controllor.fec_snd_cache.emplace_back(clone_into_pair(data.get(), data_size));

	size_t fec_data_buffer_size = udp_session_ptr->wrapper_ptr->pack_data_with_fec(feature_value, data.get(), data_size, fec_controllor.fec_snd_sn.load(), fec_controllor.fec_snd_sub_sn++);
	data_sender(udp_session_ptr, std::move(data), fec_data_buffer_size);

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
			data_sender(udp_session_ptr, std::move(fec_redundant_buffer));
		}
		fec_controllor.fec_snd_cache.clear();
		fec_controllor.fec_snd_sub_sn.store(0);
		fec_controllor.fec_snd_sn++;
	}
}

void client_mode::fec_find_missings(udp_mappings *udp_session_ptr, fec_control_data &fec_controllor, uint32_t fec_sn, uint8_t max_fec_data_count)
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
			std::shared_ptr<udp::endpoint> udp_endpoint = udp_session_ptr->ingress_source_endpoint;
			udp_access_point->async_send_out(std::move(data), missed_data_ptr, missed_data_size, *udp_endpoint);
			fec_recovery_count++;
		}

		fec_controllor.fec_rcv_restored.insert(sn);
	}
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

		if (time_elapsed > CLEANUP_WAITS / 2 &&
			forwarder_ptr != nullptr)
			forwarder_ptr->stop();

		if (time_elapsed <= CLEANUP_WAITS)
			continue;

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
		int64_t time_elapsed = time_right_now - expire_time;

		if (time_elapsed <= CLEANUP_WAITS)
			continue;

		if (time_elapsed < CLEANUP_WAITS)
		{
			if (udp_session_ptr->egress_forwarder != nullptr)
				udp_session_ptr->egress_forwarder->stop();
			continue;
		}

		std::shared_ptr<udp::endpoint> ingress_source_endpoint = udp_session_ptr->ingress_source_endpoint;
		udp_endpoint_map_to_session.erase(*ingress_source_endpoint);
		expiring_sessions.erase(iter);
	}
}

void client_mode::loop_timeout_sessions()
{
	std::vector<std::shared_ptr<forwarder>> old_forwarders;
	std::scoped_lock lockers{ mutex_udp_session_channels, mutex_expiring_sessions };
	for (auto iter = udp_session_channels.begin(), next_iter = iter; iter != udp_session_channels.end(); iter = next_iter)
	{
		++next_iter;
		uint32_t iden = iter->first;
		std::shared_ptr<udp_mappings> udp_session_ptr = iter->second;

		if (time_gap_of_ingress_receive(udp_session_ptr.get()) > current_settings.timeout &&
			time_gap_of_ingress_send(udp_session_ptr.get()) > current_settings.timeout)
		{
			if (expiring_sessions.find(udp_session_ptr) == expiring_sessions.end())
				expiring_sessions[udp_session_ptr] = right_now();

			old_forwarders.push_back(udp_session_ptr->egress_forwarder);
			udp_session_ptr->egress_forwarder->stop();
			udp_session_ptr->egress_forwarder = nullptr;
			udp_session_channels.erase(iter);
			udp_session_ptr->hopping_timestamp.store(LLONG_MAX);
		}
	}

	if (!old_forwarders.empty())
	{
		std::scoped_lock lock_expiring_forwarders{ mutex_expiring_forwarders };
		for (std::shared_ptr<forwarder> old_forwarder : old_forwarders)
			expiring_forwarders[old_forwarder] = right_now();
	}
}

void client_mode::loop_keep_alive()
{
	std::shared_lock locker{ mutex_udp_session_channels };
	for (auto &[iden, udp_session_ptr] : udp_session_channels)
	{
		if (udp_session_ptr->keep_alive_egress_timestamp.load() < right_now())
			continue;

		if (current_settings.fec_data == 0 || current_settings.fec_redundant == 0)
		{
			auto [response_packet, response_packet_size] = udp_session_ptr->wrapper_ptr->create_keep_alive_packet();
			data_sender(udp_session_ptr, std::move(response_packet), response_packet_size);
		}
		else
		{
			auto [response_packet, response_packet_size] = udp_session_ptr->wrapper_ptr->create_random_small_packet();
			fec_maker(udp_session_ptr, feature::keep_alive, std::move(response_packet), response_packet_size);
		}

		udp_session_ptr->keep_alive_egress_timestamp += current_settings.keep_alive;
	}
}

void client_mode::loop_hopping_test()
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

		udp::endpoint hopping_endpoint = udp_session_ptr->hopping_endpoint;
		uint32_t iden = udp_session_ptr->wrapper_ptr->get_iden();
		if (current_settings.fec_data == 0 || current_settings.fec_redundant == 0)
		{
			auto [response_packet, response_packet_size] = udp_session_ptr->hopping_wrapper_ptr->create_test_connection_packet(iden);
			data_sender(udp_session_ptr, hopping_endpoint, std::move(response_packet), response_packet_size);
		}
		else
		{
			auto [response_packet, response_packet_size] = udp_session_ptr->hopping_wrapper_ptr->create_small_packet(iden);
			size_t fec_data_buffer_size = udp_session_ptr->hopping_wrapper_ptr->pack_data_with_fec(feature::test_connection, response_packet.get(), response_packet_size, 0, 0);
			data_sender(udp_session_ptr, udp_session_ptr->hopping_endpoint, std::move(response_packet), fec_data_buffer_size);
		}
	}
	locker_shared.unlock();

	if (remove_later.empty())
		return;

	std::unique_lock locker{ mutex_hopping_sessions };
	for (auto &udp_session_ptr : remove_later)
	{
		hopping_sessions.erase(udp_session_ptr);
		udp_session_ptr->hopping_available.store(hop_status::pending);
		udp_session_ptr->hopping_timestamp.store(time_right_now);
	}
	locker.unlock();
}

void client_mode::find_expires(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
		return;

	loop_timeout_sessions();
	loop_hopping_test();

	timer_find_timeout.expires_after(FINDER_TIMEOUT_INTERVAL);
	timer_find_timeout.async_wait([this](const asio::error_code &e) { find_expires(e); });
}

void client_mode::expiring_wrapper_loops(const asio::error_code &e)
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

void client_mode::test_before_change(std::shared_ptr<udp_mappings> udp_mappings_ptr)
{
	auto time_right_now = right_now();
	uint32_t iden = udp_mappings_ptr->wrapper_ptr->get_iden();
	uint16_t destination_port_start = current_settings.destination_port_start;
	uint16_t destination_port_end = current_settings.destination_port_end;
	asio::error_code ec;

	if (udp_mappings_ptr->egress_hopping_forwarder == nullptr || destination_port_start == destination_port_end)
	{
		std::shared_ptr<forwarder> udp_forwarder = nullptr;
		try
		{
			auto bind_push_func = std::bind(&ttp::task_group_pool::push_task_peer, &sequence_task_pool, _1, _2, _3);
			auto bind_check_limit_func = [this](size_t number) -> bool {return sequence_task_pool.get_peer_network_task_count(number) > TASK_COUNT_LIMIT; };
			auto udp_func = std::bind(&client_mode::udp_forwarder_incoming_to_udp, this, _1, _2, _3, _4, _5);
			udp_forwarder = std::make_shared<forwarder>(io_context, bind_push_func, bind_check_limit_func, udp_mappings_ptr, udp_func, current_settings.ip_version_only);
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

		if (destination_port_start == destination_port_end)
		{
			std::shared_lock locker_egress{ udp_mappings_ptr->mutex_egress_endpoint };
			udp_mappings_ptr->hopping_endpoint = udp_mappings_ptr->egress_target_endpoint;
			locker_egress.unlock();
		}
		else
		{
			std::shared_lock locker_egress{ udp_mappings_ptr->mutex_egress_endpoint };
			uint16_t current_port_number = udp_mappings_ptr->egress_target_endpoint.port();
			locker_egress.unlock();
			uint16_t new_port_numer = generate_new_port_number(destination_port_start, destination_port_end);
			for (size_t retry_times = 0; new_port_numer == current_port_number && retry_times < RETRY_TIMES; retry_times++)
			{
				new_port_numer = generate_new_port_number(destination_port_start, destination_port_end);
			}
			std::shared_lock locker{ mutex_target_address };
			asio::ip::address temp_address = *target_address;
			locker.unlock();
			udp_mappings_ptr->hopping_endpoint.address(temp_address);
			udp_mappings_ptr->hopping_endpoint.port(new_port_numer);
		}

		std::shared_ptr<forwarder> new_forwarder = udp_forwarder;
		std::vector<uint8_t> keep_alive_packet = create_empty_data(current_settings.encryption_password, current_settings.encryption, EMPTY_PACKET_SIZE);
		udp_mappings_ptr->wrapper_ptr->write_iden(keep_alive_packet.data());

		if (current_settings.ip_version_only == ip_only_options::ipv4)
			new_forwarder->send_out(std::move(keep_alive_packet), local_empty_target_v4, ec);
		else
			new_forwarder->send_out(std::move(keep_alive_packet), local_empty_target_v6, ec);

		if (ec)
		{
			udp_mappings_ptr->hopping_timestamp.store(time_right_now + current_settings.dynamic_port_refresh);
			return;
		}

		new_forwarder->async_receive();
		if (udp_mappings_ptr->egress_hopping_forwarder != nullptr)
		{
			udp_mappings_ptr->egress_hopping_forwarder->pause(true);
			std::scoped_lock lock_expiring_forwarders{ mutex_expiring_forwarders };
			expiring_forwarders[udp_mappings_ptr->egress_hopping_forwarder] = right_now();
		}
		udp_mappings_ptr->egress_hopping_forwarder = new_forwarder;
	}
	else
	{
		uint16_t current_port_number = udp_mappings_ptr->hopping_endpoint.port();
		uint16_t new_port_numer = generate_new_port_number(destination_port_start, destination_port_end);
		for (size_t retry_times = 0; new_port_numer == current_port_number && retry_times < RETRY_TIMES; retry_times++)
		{
			new_port_numer = generate_new_port_number(destination_port_start, destination_port_end);
		}
		udp_mappings_ptr->hopping_endpoint.port(new_port_numer);
	}

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

void client_mode::switch_new_port(std::shared_ptr<udp_mappings> udp_mappings_ptr)
{
	udp_mappings_ptr->hopping_timestamp.store(right_now() + current_settings.dynamic_port_refresh);
	udp_mappings_ptr->hopping_available.store(hop_status::pending);

	{
		udp_mappings_ptr->egress_previous_target_endpoint = udp_mappings_ptr->egress_target_endpoint;
		udp_mappings_ptr->egress_target_endpoint = udp_mappings_ptr->hopping_endpoint;
	}

	std::shared_ptr<forwarder> new_forwarder = udp_mappings_ptr->egress_hopping_forwarder;
	std::shared_ptr<forwarder> old_forwarder = udp_mappings_ptr->egress_forwarder;
	udp_mappings_ptr->egress_forwarder = new_forwarder;
	udp_mappings_ptr->egress_hopping_forwarder.reset();

	std::scoped_lock lock_expiring_forwarders{ mutex_expiring_forwarders };
	if (expiring_forwarders.find(old_forwarder) == expiring_forwarders.end())
		expiring_forwarders.insert({ old_forwarder, right_now() });
}

void client_mode::verify_testing_response(std::shared_ptr<udp_mappings> udp_session_ptr, std::unique_ptr<uint8_t[]> data, size_t plain_size)
{
	uint8_t *data_ptr = data.get();
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

	if (udp_session_ptr->egress_hopping_forwarder != nullptr &&
		udp_session_ptr->hopping_available.load() == hop_status::testing)
	{
		std::unique_lock locker{ mutex_hopping_sessions };
		hopping_sessions.erase(udp_session_ptr);
		locker.unlock();
		udp_session_ptr->mapping_function();
	}
}

void client_mode::keep_alive(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
		return;

	loop_keep_alive();

	timer_keep_alive.expires_after(seconds{ current_settings.keep_alive });
	timer_keep_alive.async_wait([this](const asio::error_code &e) { keep_alive(e); });
}

void client_mode::log_status(const asio::error_code &e)
{
	if (e == asio::error::operation_aborted)
		return;

	loop_get_status();

	timer_status_log.expires_after(LOGGING_GAP);
	timer_status_log.async_wait([this](const asio::error_code &e) { log_status(e); });
}

void client_mode::loop_get_status()
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
