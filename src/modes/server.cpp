#include "server.hpp"
#include <asio/experimental/awaitable_operators.hpp>
#include "../shares/data_operations.hpp"
#include "../networks/dns_helper.hpp"

using asio::ip::tcp;
using asio::awaitable;
using asio::co_spawn;
using asio::detached;
using namespace asio::experimental::awaitable_operators;

namespace modes
{
	awaitable<void> server_mode::listener_ipv4_udp(uint16_t port)
	{
		try
		{
			udp::endpoint binding_endpoint(udp::v4(), port);
			udp_socket listener_socket(network_io, binding_endpoint);
			ipv4_udp_servers.emplace_back(&listener_socket);
			co_spawn(network_io, udp_listener_incoming(std::move(listener_socket)), detached);
		}
		catch (std::exception &e)
		{
			std::cerr << "IPv4 (port " << port << ") udphop_listen Exception: " << e.what() << "\n";
			startup_has_error = true;
		}
		co_return;
	}

	awaitable<void> server_mode::listener_ipv4_udp(asio::ip::address_v4 address, uint16_t port)
	{
		try
		{
			udp::endpoint binding_endpoint(address, port);
			udp_socket listener_socket(network_io, binding_endpoint);
			ipv4_udp_servers.emplace_back(&listener_socket);
			co_spawn(network_io, udp_listener_incoming(std::move(listener_socket)), detached);
		}
		catch (std::exception &e)
		{
			std::cerr << "IPv4 (" << address << ":" << port << ") udphop_listen Exception: " << e.what() << "\n";
			startup_has_error = true;
		}
		co_return;
	}

	awaitable<void> server_mode::listener_ipv6_udp(uint16_t port)
	{
		try
		{
			udp::endpoint binding_endpoint(udp::v6(), port);
			udp_socket listener_socket(network_io, binding_endpoint);
			ipv6_udp_servers.emplace_back(&listener_socket);
			co_spawn(network_io, udp_listener_incoming(std::move(listener_socket)), detached);
		}
		catch (std::exception &e)
		{
			std::cerr << "IPv6 (port " << port << ") udphop_listen Exception: " << e.what() << "\n";
			if constexpr (linux_system)
			{
				std::cerr << "Fallback to IPv4\n";
				co_spawn(network_io, listener_ipv4_udp(port), detached);
			}
			else
			{
				startup_has_error = true;
			}
		}
		co_return;
	}

	awaitable<void> server_mode::listener_ipv6_udp(asio::ip::address_v6 address, uint16_t port)
	{
		try
		{
			udp::endpoint binding_endpoint(address, port);
			udp_socket listener_socket(network_io, binding_endpoint);
			ipv6_udp_servers.emplace_back(&listener_socket);
			co_spawn(network_io, udp_listener_incoming(std::move(listener_socket)), detached);
		}
		catch (std::exception &e)
		{
			std::cerr << "IPv6 ([" << address << "]:" << port << ") udphop_listen Exception: " << e.what() << "\n";
			startup_has_error = true;
		}
		co_return;
	}

	asio::awaitable<void> server_mode::udp_listener_incoming(udp_socket listener_socket)
	{
		udp::endpoint from_udp_endpoint;

		while (listener_socket.is_open())
		{
			asio::error_code ec;
			uint16_t port = 0;
			std::unique_ptr<uint8_t[]> data = std::make_unique_for_overwrite<uint8_t[]>(BUFFER_SIZE + BUFFER_EXPAND_SIZE);
			uint8_t *data_buffer_ptr = data.get() + RAW_HEADER_FEC_SIZE;
			size_t bytes_read = co_await listener_socket.async_receive_from(asio::buffer(data_buffer_ptr, BUFFER_SIZE), from_udp_endpoint, asio::redirect_error(asio::use_awaitable, ec));
			if (ec || bytes_read == 0)
				continue;

			uint8_t *data_ptr = data_buffer_ptr;
			status_counters.ingress_raw_traffic += bytes_read;
			status_counters.ingress_raw_traffic_each_second += bytes_read;
			if (stun_header != nullptr)
			{
				uint32_t ipv4_address = 0;
				uint16_t ipv4_port = 0;
				std::array<uint8_t, 16> ipv6_address{};
				uint16_t ipv6_port = 0;
				if (rfc8489::unpack_address_port(data_ptr, stun_header.get(), ipv4_address, ipv4_port, ipv6_address, ipv6_port))
				{
					save_external_ip_address(ipv4_address, ipv4_port, ipv6_address, ipv6_port);
					continue;
				}
			}

			if (bytes_read < RAW_HEADER_SIZE)
				continue;

			co_spawn(task_context, udp_listener_incoming_unpack(listener_socket, from_udp_endpoint, std::move(data), data_ptr, bytes_read), detached);
		}
	}

	asio::awaitable<void> server_mode::udp_listener_incoming_unpack(udp_socket &listener_socket, udp::endpoint from_udp_endpoint, std::unique_ptr<uint8_t[]> original_cache, uint8_t *data_ptr, size_t data_size)
	{
		auto [error_message, plain_size] = co_await cipher_operations.async_decrypt(task_context, data_ptr, (int)data_size);
		if (!error_message.empty() || plain_size == 0)
			co_return;

		uint32_t iden = packet::data_wrapper::extract_iden(data_ptr);
		if (iden == 0)
		{
			udp_listener_response_test_connection(listener_socket, data_ptr, plain_size, from_udp_endpoint);
			co_return;
		}

		std::shared_ptr<udp_mappings> udp_session_ptr = nullptr;
		if (auto wrapper_channel_iter = udp_session_channels.find(iden);
			wrapper_channel_iter == udp_session_channels.end())
		{
			udp_listener_incoming_new_connection(data_ptr, plain_size, from_udp_endpoint, listener_socket);
			co_return;
		}
		else udp_session_ptr = wrapper_channel_iter->second;

		auto [packet_timestamp, feature_value, received_data, received_size] = udp_session_ptr->wrapper_ptr->receive_data(data_ptr, plain_size);
		if (received_size == 0 || packet_timestamp == 0)
			co_return;

		if (feature_value == feature::test_connection)
		{
			udp_listener_response_test_connection(listener_socket, data_ptr, plain_size, from_udp_endpoint);
			co_return;
		}

		auto timestamp = right_now();
		if (calculate_difference<int64_t>((uint32_t)timestamp, packet_timestamp) > TIME_GAP)
			co_return;

		udp_session_ptr->ingress_sender.store(&listener_socket);

		std::shared_ptr<udp_socket> local_udp = udp_session_ptr->local_udp;
		if (local_udp == nullptr)
			co_return;

		if (fec_enabled)
		{
			auto [fec_data_ptr, fec_data_size] = fec_unpack(udp_session_ptr, data_ptr, plain_size);
			if (fec_data_ptr == nullptr)
				co_return;
			received_data = fec_data_ptr;
			received_size = fec_data_size;
		}

		if (std::shared_ptr<udp::endpoint> ingress_source_endpoint = load_atomic_ptr(udp_session_ptr->ingress_source_endpoint);
			ingress_source_endpoint == nullptr || *ingress_source_endpoint != from_udp_endpoint)
			std::atomic_store(&(udp_session_ptr->ingress_source_endpoint), std::make_shared<udp::endpoint>(from_udp_endpoint));

		asio::error_code ec;
		switch (feature_value)
		{
		case feature::keep_alive:
		{
			uint8_t *response_init_ptr = data_ptr + RAW_HEADER_FEC_SIZE;
			auto [response_packet_ptr, response_packet_size] = udp_session_ptr->wrapper_ptr->create_keep_alive_response_packet(response_init_ptr);
			if (fec_enabled)
				std::tie(response_packet_ptr, response_packet_size) = udp_session_ptr->wrapper_ptr->prepend_header_fec(feature::keep_alive_response, response_init_ptr, response_packet_size, 0, 0);

			auto [error_message, cipher_size] = co_await cipher_operations.async_encrypt(network_io, response_packet_ptr, (int)response_packet_size);
			if (!error_message.empty() || cipher_size == 0)
				break;
			co_await listener_socket.async_send_to(asio::buffer(response_packet_ptr, cipher_size), from_udp_endpoint, asio::redirect_error(asio::use_awaitable, ec));
			break;
		}
		case feature::test_connection:
			break;
		case feature::keep_alive_response:
			break;
		case feature::raw_data:
			co_await local_udp->async_send_to(asio::buffer(received_data, received_size), *udp_target, asio::redirect_error(asio::use_awaitable, ec));
			status_counters.egress_raw_traffic += received_size;
			status_counters.egress_raw_traffic_each_second += received_size;
			udp_session_ptr->last_ingress_receive_time.store(right_now());
			udp_session_ptr->last_egress_send_time.store(right_now());
			break;
		default:
			break;
		}
	}

	void server_mode::udp_listener_incoming_new_connection(uint8_t *data_ptr, size_t data_size, udp::endpoint from_udp_endpoint, udp_socket &listener_socket)
	{
		if (data_size == 0)
			return;

		uint32_t iden = packet::data_wrapper::extract_iden(data_ptr);
		std::shared_ptr<udp_mappings> udp_session_ptr = std::make_shared<udp_mappings>();
		udp_session_ptr->wrapper_ptr = std::make_unique<packet::data_wrapper>(iden);
		packet::data_wrapper *data_wrapper_ptr = udp_session_ptr->wrapper_ptr.get();

		auto [packet_timestamp, feature_value, received_data, received_size] = data_wrapper_ptr->receive_data(data_ptr, data_size);
		if (received_size == 0)
			return;

		auto timestamp = right_now();
		if (calculate_difference<int64_t>((uint32_t)timestamp, packet_timestamp) > TIME_GAP)
			return;

		udp_session_ptr->ingress_source_endpoint = std::make_shared<udp::endpoint>(from_udp_endpoint);
		udp_session_ptr->ingress_sender.store(&listener_socket);

		if (fec_enabled)
		{
			size_t K = current_settings.fec_original_packet_count;
			size_t N = K + current_settings.fec_redundant_packet_count;
			udp_session_ptr->fec_ingress_control.fecc.reset_martix(K, N);
		
			auto [fec_data_ptr, fec_data_size] = fec_unpack(udp_session_ptr, data_ptr, data_size);
			if (fec_data_ptr == nullptr)
				return;
			received_data = fec_data_ptr;
			received_size = fec_data_size;
		}

		switch (feature_value)
		{
		case feature::keep_alive:
		{
			if (fec_enabled)
			{
				auto [response_packet, response_packet_size] = udp_session_ptr->wrapper_ptr->create_random_small_packet();
				size_t packed_data_size = udp_session_ptr->wrapper_ptr->pack_data_with_fec(feature::keep_alive_response, response_packet.get(), response_packet_size, 0, 0);
				auto [error_message, cipher_size] = encrypt_data(current_settings.encryption_password, current_settings.encryption, response_packet.get(), (int)response_packet_size);
				if (!error_message.empty() || cipher_size == 0)
					break;
				auto asio_buffer = asio::buffer(response_packet.get(), cipher_size);
				listener_socket.async_send_to(asio_buffer, from_udp_endpoint,
					[data_ = std::move(response_packet)](const asio::error_code &error, size_t bytes_transferred) {});
				status_counters.egress_raw_traffic += cipher_size;
				status_counters.egress_raw_traffic_each_second += cipher_size;
			}
			else
			{
				auto [response_packet, response_packet_size] = udp_session_ptr->wrapper_ptr->create_keep_alive_response_packet();
				auto [error_message, cipher_size] = encrypt_data(current_settings.encryption_password, current_settings.encryption, response_packet.get(), (int)response_packet_size);
				if (!error_message.empty() || cipher_size == 0)
					break;
				auto asio_buffer = asio::buffer(response_packet.get(), cipher_size);
				listener_socket.async_send_to(asio_buffer, from_udp_endpoint,
					[data_ = std::move(response_packet)](const asio::error_code &error, size_t bytes_transferred) {});
				status_counters.egress_raw_traffic += cipher_size;
				status_counters.egress_raw_traffic_each_second += cipher_size;
			}
			break;
		}
		case feature::test_connection:
			if (fec_enabled)
			{
				auto [response_packet, response_packet_size] = udp_session_ptr->wrapper_ptr->create_random_small_packet();
				size_t fec_data_buffer_size = udp_session_ptr->wrapper_ptr->pack_data_with_fec(feature_value, response_packet.get(), response_packet_size, 0, 0);
				auto asio_buffer = asio::buffer(response_packet.get(), response_packet_size);
				listener_socket.async_send_to(asio_buffer, from_udp_endpoint,
					[data_ = std::move(response_packet)](const asio::error_code &error, size_t bytes_transferred) {});
			}
			else
			{
				auto [response_packet, response_packet_size] = udp_session_ptr->wrapper_ptr->create_test_connection_packet();
				auto asio_buffer = asio::buffer(response_packet.get(), response_packet_size);
				listener_socket.async_send_to(asio_buffer, from_udp_endpoint,
					[data_ = std::move(response_packet)](const asio::error_code &error, size_t bytes_transferred) {});
			}
			break;
		case feature::keep_alive_response:
			break;
		case feature::raw_data:
			if (create_new_udp_connection(received_data, received_size, udp_session_ptr, from_udp_endpoint))
			{
				udp_session_channels[iden] = udp_session_ptr;
				co_spawn(network_io, udp_connector_incoming(udp_session_ptr), detached);
			}
			break;
		default:
			break;
		}
	}

	bool server_mode::create_new_udp_connection(const uint8_t *data_ptr, size_t data_size, std::shared_ptr<udp_mappings> udp_session_ptr, const udp::endpoint &from_udp_endpoint)
	{
		bool connect_success = false;

		asio::error_code ec;
		std::shared_ptr<udp_socket> local_udp = std::make_shared<udp_socket>(network_io);
		
		if (udp_target->address().is_v4())
			local_udp->open(udp::v4(), ec);
		if (udp_target->address().is_v6())
			local_udp->open(udp::v6(), ec);

		if (ec)
			return false;

		if (udp_target != nullptr || update_local_udp_target())
		{
			std::unique_ptr<uint8_t[]> data_copy = std::make_unique<uint8_t[]>(data_size);
			std::copy_n(data_ptr, data_size, data_copy.get());
			auto asio_buffer = asio::buffer(data_copy.get(), data_size);
			local_udp->async_send_to(asio_buffer, *udp_target, [data_ = std::move(data_copy)](auto, auto) {});
			status_counters.egress_raw_traffic += data_size;
			status_counters.egress_raw_traffic_each_second += data_size;
		}

		if (ec)
		{
			connect_success = false;
		}
		else
		{
			udp_session_ptr->local_udp = local_udp;
			udp_session_ptr->last_ingress_receive_time.store(right_now());
			udp_session_ptr->last_ingress_send_time.store(right_now());
			udp_session_ptr->last_egress_receive_time.store(right_now());
			udp_session_ptr->last_egress_send_time.store(right_now());
			connect_success = true;
		}

		return connect_success;
	}

	asio::awaitable<void> server_mode::udp_connector_incoming(std::weak_ptr<udp_mappings> udp_session_weak_ptr)
	{
		std::shared_ptr<udp_mappings> udp_session_ptr = udp_session_weak_ptr.lock();
		if (udp_session_ptr == nullptr)
			co_return;

		udp::endpoint from_udp_endpoint;
		asio::error_code ec;

		while (udp_session_ptr->local_udp != nullptr && udp_session_ptr->local_udp->is_open())
		{
			std::unique_ptr<uint8_t[]> data = std::make_unique_for_overwrite<uint8_t[]>(BUFFER_SIZE + BUFFER_EXPAND_SIZE);
			uint8_t *data_buffer_ptr = data.get() + RAW_HEADER_FEC_SIZE;
			size_t bytes_read = co_await udp_session_ptr->local_udp->async_receive_from(asio::buffer(data_buffer_ptr, BUFFER_SIZE), from_udp_endpoint, asio::redirect_error(asio::use_awaitable, ec));
			if (ec)
				continue;

			if (bytes_read == 0)
				continue;

			if (fec_enabled)
			{
				fec_maker(udp_session_ptr, std::move(data), data_buffer_ptr, bytes_read);
			}
			else
			{
				std::shared_ptr<uint8_t[]> original_cache_sp = std::move(data);
				auto [packed_data, packed_data_size] = udp_session_ptr->wrapper_ptr->prepend_header(feature::raw_data, data_buffer_ptr, bytes_read);
				parallel_pool.submit_detach([this, udp_session_ptr, original_cache_sp, packed_data, packed_data_size]() mutable
					{
						auto [error_message, cipher_size] = encrypt_data(current_settings.encryption_password, current_settings.encryption, packed_data, (int)packed_data_size);
						if (!error_message.empty() || cipher_size == 0)
							return;
						auto asio_buffer = asio::buffer(packed_data, cipher_size);
						udp_socket *ingress_sender = udp_session_ptr->ingress_sender.load();
						std::shared_ptr<udp::endpoint> ingress_source_endpoint = load_atomic_ptr(udp_session_ptr->ingress_source_endpoint);
						ingress_sender->async_send_to(asio_buffer, *ingress_source_endpoint, [original_cache_sp](auto, auto) {});
						status_counters.egress_raw_traffic += cipher_size;
						status_counters.egress_raw_traffic_each_second += cipher_size;
					});
			}

			udp_session_ptr->last_egress_receive_time.store(right_now());
			udp_session_ptr->last_ingress_send_time.store(right_now());
		}

		if (udp_session_ptr->local_udp == nullptr)
		{
			std::cout << "udp_session_ptr->local_udp == nullptr\n";
			co_return;
		}

		if(udp_session_ptr->local_udp->is_open())
			std::cout << "udp_session_ptr->local_udp loop ends\n";
		else
			std::cout << "udp_session_ptr->local_udp is closed\n";
	}

	void server_mode::udp_listener_response_test_connection(udp_socket &listener_socket, uint8_t *data_ptr, size_t data_size, udp::endpoint from_udp_endpoint)
	{
		if (data_size == 0)
			return;

		packet::data_wrapper wrapper_zero(0);

		auto [packet_timestamp, feature_value, received_data, received_size] = wrapper_zero.receive_data(data_ptr, data_size);
		if (received_size == 0 || feature_value != feature::test_connection)
			return;

		auto timestamp = right_now();
		if (calculate_difference<int64_t>((uint32_t)timestamp, packet_timestamp) > TIME_GAP)
			return;

		uint32_t test_iden = wrapper_zero.unpack_test_iden(received_data);
		parallel_pool.submit_detach([this, &listener_socket, from_udp_endpoint, feature_value, test_iden]()
			{
				packet::data_wrapper wrapper_zero(test_iden);
				std::unique_ptr<uint8_t[]> cache_array = std::make_unique_for_overwrite<uint8_t[]>(BUFFER_SIZE + RAW_HEADER_FEC_SIZE);
				uint8_t *data_ptr = cache_array.get() + RAW_HEADER_FEC_SIZE;
				uint8_t *response_packet_ptr;
				size_t response_packet_size;
				if (fec_enabled)
					std::tie(response_packet_ptr, response_packet_size) = wrapper_zero.create_test_connection_packet_with_fec(data_ptr, test_iden, 0, 0);
				else
					std::tie(response_packet_ptr, response_packet_size) = wrapper_zero.create_test_connection_packet(data_ptr, test_iden);

				auto [error_message, cipher_size] = encrypt_data(current_settings.encryption_password, current_settings.encryption, response_packet_ptr, (int)response_packet_size);
				if (!error_message.empty() || cipher_size == 0)
					return;
				auto asio_buffer = asio::buffer(response_packet_ptr, cipher_size);
				listener_socket.async_send_to(asio_buffer, from_udp_endpoint, [data_ = std::move(cache_array)](auto, auto) {});
			});
	}

	bool server_mode::update_local_udp_target()
	{
		bool update_success = false;
		asio::error_code ec;
		udp::resolver resolver(network_io);
		for (int i = 0; i < RETRY_TIMES; ++i)
		{
			const std::string &destination_address = current_settings.destination_address_list.front();
			uint16_t destination_port = current_settings.destination_ports.front();
			udp::resolver::results_type udp_endpoints = resolver.resolve(destination_address, "", ec);
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
				std::cerr << error_message << "\n";
				print_message_to_file(error_message, current_settings.log_messages);
				std::this_thread::sleep_for(std::chrono::seconds(RETRY_WAITS));
			}
			else
			{
				udp_target = std::make_unique<udp::endpoint>(*udp_endpoints.begin());
				udp_target->port(destination_port);
				update_success = true;
				break;
			}
		}
		return update_success;
	}

	asio::awaitable<void> server_mode::update_local_udp_target_task()
	{
		asio::error_code ec;
		udp::resolver resolver(network_io);
		for (int i = 0; i < RETRY_TIMES; ++i)
		{
			const std::string &destination_address = current_settings.destination_address_list.front();
			uint16_t destination_port = current_settings.destination_ports.front();
			udp::resolver::results_type udp_endpoints = co_await resolver.async_resolve(destination_address, "", asio::redirect_error(asio::use_awaitable, ec));
			std::chrono::time_point deadline = std::chrono::steady_clock::now() + FINDER_TIMEOUT_INTERVAL;
			if (ec)
			{
				std::string error_message = time_to_string_with_square_brackets() + ec.message();
				std::cerr << error_message << "\n";
				print_message_to_file(error_message + "\n", current_settings.log_messages);
				timer_update_local_target.expires_at(deadline);
				co_await timer_update_local_target.async_wait(asio::use_awaitable);
			}
			else if (udp_endpoints.size() == 0)
			{
				std::string error_message = time_to_string_with_square_brackets() + "destination address not found\n";
				std::cerr << error_message << "\n";
				print_message_to_file(error_message, current_settings.log_messages);
				timer_update_local_target.expires_at(deadline);
				co_await timer_update_local_target.async_wait(asio::use_awaitable);
			}
			else
			{
				udp_target = std::make_unique<udp::endpoint>(*udp_endpoints.begin());
				udp_target->port(destination_port);
				break;
			}
		}
		timer_update_local_target.expires_at(std::chrono::steady_clock::now() + std::chrono::seconds(RETRY_TIMES));
		co_await timer_update_local_target.async_wait(asio::use_awaitable);
		co_spawn(network_io, update_local_udp_target_task(), detached);
	}

	void server_mode::fec_maker(std::shared_ptr<udp_mappings> udp_session_ptr, std::unique_ptr<uint8_t[]> original_cache, uint8_t *data, size_t data_size)
	{
		fec_control_data &fec_controllor = udp_session_ptr->fec_ingress_control;
		if (data != nullptr && data_size > 0)
		{
			fec_controllor.fec_snd_cache.emplace_back(clone_into_pair(data, data_size));
			auto [packed_data, packed_data_size] = udp_session_ptr->wrapper_ptr->prepend_header_fec(feature::raw_data, data, data_size, fec_controllor.fec_snd_sn.load(), fec_controllor.fec_snd_sub_sn++);

			std::shared_ptr<uint8_t[]> original_cache_sp = std::move(original_cache);
			parallel_pool.submit_detach([this, udp_session_ptr, original_cache_sp, packed_data, packed_data_size]() mutable
				{
					auto [error_message, cipher_size] = encrypt_data(current_settings.encryption_password, current_settings.encryption, packed_data, (int)packed_data_size);
					if (!error_message.empty() || cipher_size == 0)
						return;
					auto asio_buffer = asio::buffer(packed_data, cipher_size);
					udp_socket *ingress_sender = udp_session_ptr->ingress_sender.load();
					std::shared_ptr<udp::endpoint> ingress_source_endpoint = load_atomic_ptr(udp_session_ptr->ingress_source_endpoint);
					ingress_sender->async_send_to(asio_buffer, *ingress_source_endpoint, [original_cache_sp](auto, auto) {});
					status_counters.egress_raw_traffic += cipher_size;
					status_counters.egress_raw_traffic_each_second += cipher_size;
				});
		}

		if (fec_controllor.fec_snd_cache.size() == current_settings.fec_original_packet_count)
		{
			auto [array_data, fec_align_length, total_size] = compact_into_container(fec_controllor.fec_snd_cache);
			auto redundants = fec_controllor.fecc.encode(array_data.get(), total_size, fec_align_length);
			for (auto &data_ptr : redundants)
			{
				auto [fec_redundant_buffer, fec_redundant_buffer_size] = udp_session_ptr->wrapper_ptr->pack_data_with_fec(
					feature::raw_data,
					(const uint8_t *)data_ptr.get(), fec_align_length,
					fec_controllor.fec_snd_sn.load(), fec_controllor.fec_snd_sub_sn++);

				std::shared_ptr<uint8_t[]> fec_redundant_buffer_sp = std::move(fec_redundant_buffer);
				parallel_pool.submit_detach([this, udp_session_ptr, fec_redundant_buffer_sp, fec_redundant_buffer_size]() mutable
					{
						auto [error_message, cipher_size] = encrypt_data(current_settings.encryption_password, current_settings.encryption, fec_redundant_buffer_sp.get(), (int)fec_redundant_buffer_size);
						if (!error_message.empty() || cipher_size == 0)
							return;
						auto asio_buffer = asio::buffer(fec_redundant_buffer_sp.get(), cipher_size);
						udp_socket *ingress_sender = udp_session_ptr->ingress_sender.load();
						std::shared_ptr<udp::endpoint> ingress_source_endpoint = load_atomic_ptr(udp_session_ptr->ingress_source_endpoint);
						ingress_sender->async_send_to(asio_buffer, *ingress_source_endpoint, [fec_redundant_buffer_sp](auto, auto) {});
						status_counters.egress_raw_traffic += cipher_size;
						status_counters.egress_raw_traffic_each_second += cipher_size;
					});
			}
			fec_controllor.fec_snd_cache.clear();
			fec_controllor.fec_snd_sub_sn.store(0);
			fec_controllor.fec_snd_sn++;
		}
	}

	std::pair<uint8_t *, size_t> server_mode::fec_unpack(std::shared_ptr<udp_mappings> &udp_session_ptr, uint8_t *original_data_ptr, size_t plain_size)
	{
		uint8_t *data_ptr = nullptr;
		size_t packet_data_size = 0;
		auto [packet_header, fec_data_ptr, fec_data_size] = udp_session_ptr->wrapper_ptr->receive_data_with_fec(original_data_ptr, plain_size);
		uint32_t fec_sn = packet_header.sn;
		uint8_t fec_sub_sn = packet_header.sub_sn;

		std::pair<std::unique_ptr<uint8_t[]>, size_t> &original_data = udp_session_ptr->fec_ingress_control.fec_rcv_cache[fec_sn][fec_sub_sn];
		original_data.first = std::make_unique_for_overwrite<uint8_t[]>(fec_data_size);
		original_data.second = fec_data_size;
		std::copy_n(fec_data_ptr, fec_data_size, original_data.first.get());
		fec_find_missings(udp_session_ptr.get(), udp_session_ptr->fec_ingress_control, fec_sn, current_settings.fec_original_packet_count);

		if (packet_header.sub_sn < current_settings.fec_original_packet_count)
		{
			data_ptr = fec_data_ptr;
			packet_data_size = fec_data_size;
			status_counters.fec_raw_packet_count++;
		}
		else status_counters.fec_raw_redund_count++;

		return { data_ptr, packet_data_size };
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
				udp_session_ptr->local_udp->async_send_to(asio::buffer(missed_data_ptr, missed_data_size), *udp_target,
					[data_ = std::move(data)](const asio::error_code &error, size_t bytes_transferred) {});
				status_counters.fec_recovery_count++;
			}

			fec_controllor.fec_rcv_restored.insert(sn);
		}
	}

	asio::awaitable<void> server_mode::cleanup_timedout_sessions()
	{
		std::chrono::time_point deadline = std::chrono::steady_clock::now() + FINDER_TIMEOUT_INTERVAL;
		timer_find_timeout.expires_at(deadline);
		co_await timer_find_timeout.async_wait(asio::use_awaitable);

		for (auto iter = udp_session_channels.begin(), next_iter = iter; iter != udp_session_channels.end(); iter = next_iter)
		{
			++next_iter;
			std::shared_ptr<udp_mappings> udp_session_ptr = iter->second;
			uint32_t iden = udp_session_ptr->wrapper_ptr->get_iden();
			if (time_gap_of_egress_receive(udp_session_ptr.get()) > current_settings.timeout ||
				time_gap_of_egress_send(udp_session_ptr.get()) > current_settings.timeout)
			{
				udp_session_ptr->local_udp->close();
				udp_session_ptr->local_udp.reset();
				udp_session_channels.erase(iter);
			}
		}
		co_spawn(network_io, cleanup_timedout_sessions(), detached);
	}

	asio::awaitable<void> server_mode::session_keep_alive()
	{
		std::chrono::time_point deadline = std::chrono::steady_clock::now() + KEEP_ALIVE_UPDATE_INTERVAL;
		timer_keep_alive.expires_at(deadline);
		co_await timer_keep_alive.async_wait(asio::use_awaitable);

		for (auto &[iden, udp_session_ptr] : udp_session_channels)
		{
			if (udp_session_ptr->keep_alive_ingress_timestamp.load() < right_now())
				continue;

			parallel_pool.submit_detach([this, udp_session_ptr]()
				{
					std::shared_ptr<udp::endpoint> ingress_source_endpoint = load_atomic_ptr(udp_session_ptr->ingress_source_endpoint);
					std::unique_ptr<uint8_t[]> cache_array = std::make_unique_for_overwrite<uint8_t[]>(BUFFER_SIZE + RAW_HEADER_FEC_SIZE);
					uint8_t *data_ptr = cache_array.get() + RAW_HEADER_FEC_SIZE;
					uint8_t *response_packet_ptr;
					size_t response_packet_size;
					if (fec_enabled)
						std::tie(response_packet_ptr, response_packet_size) = udp_session_ptr->wrapper_ptr->create_keep_alive_packet_with_fec(data_ptr, 0, 0);
					else
						std::tie(response_packet_ptr, response_packet_size) = udp_session_ptr->wrapper_ptr->create_keep_alive_packet(data_ptr);

					auto [error_message, cipher_size] = encrypt_data(current_settings.encryption_password, current_settings.encryption, response_packet_ptr, (int)response_packet_size);
					if (!error_message.empty() || cipher_size == 0)
						return;
					auto asio_buffer = asio::buffer(response_packet_ptr, cipher_size);
					udp_session_ptr->ingress_sender.load()->async_send_to(asio_buffer, *ingress_source_endpoint, [data_ = std::move(cache_array)](auto, auto) {});
					udp_session_ptr->keep_alive_ingress_timestamp += current_settings.keep_alive;
				});
		}
		co_spawn(network_io, session_keep_alive(), detached);
	}

	asio::awaitable<void> server_mode::send_stun_request()
	{
		if (current_settings.stun_server.empty())
			co_return;
		if (ipv4_udp_servers.empty() && ipv6_udp_servers.empty())
			co_return;

		std::chrono::time_point deadline = std::chrono::steady_clock::now() + STUN_RESEND;
		timer_stun.expires_at(deadline);
		co_await timer_stun.async_wait(asio::use_awaitable);

		asio::error_code ec;
		udp::resolver resolver(network_io);
		udp::resolver::results_type remote_addresses = co_await resolver.async_resolve(current_settings.stun_server, "3478", asio::redirect_error(asio::use_awaitable, ec));

		if (ec)
		{
			co_spawn(network_io, send_stun_request(), detached);
			co_return;
		}

		size_t header_size = sizeof(rfc8489::stun_header);
		std::vector<udp::endpoint> stun_servers;
		auto [stun_servers_ipv4, stun_servers_ipv6] = split_resolved_addresses(remote_addresses);

		if (!ipv4_udp_servers.empty())
		{
			udp_socket *ipv4_sender = ipv4_udp_servers.front();
			for (auto &target_endpoint : stun_servers_ipv4)
			{
				std::unique_ptr<uint8_t[]> data = std::make_unique_for_overwrite<uint8_t[]>(header_size);
				std::copy_n((uint8_t *)stun_header.get(), header_size, data.get());
				auto asio_buffer = asio::buffer(data.get(), header_size);
				ipv4_sender->async_send_to(asio_buffer, target_endpoint,
					[data_ = std::move(data)](const asio::error_code &error, size_t bytes_transferred) {});
			}
		}

		if (!ipv6_udp_servers.empty())
		{
			udp_socket *ipv6_sender = ipv6_udp_servers.front();
			for (auto &target_endpoint : stun_servers_ipv6)
			{
				std::unique_ptr<uint8_t[]> data = std::make_unique_for_overwrite<uint8_t[]>(header_size);
				std::copy_n((uint8_t *)stun_header.get(), header_size, data.get());
				auto asio_buffer = asio::buffer(data.get(), header_size);
				ipv6_sender->async_send_to(asio_buffer, target_endpoint,
					[data_ = std::move(data)](const asio::error_code &error, size_t bytes_transferred) {});
			}
		}

		co_spawn(network_io, send_stun_request(), detached);
	}

	void server_mode::save_external_ip_address(uint32_t ipv4_address, uint16_t ipv4_port, const std::array<uint8_t, 16> &ipv6_address, uint16_t ipv6_port)
	{
		std::string v4_info;
		std::string v6_info;
		static const std::array<uint8_t, 16> zero_value_array{};

		if (ipv4_address != 0 && ipv4_port != 0 && (external_ipv4_address.load() != ipv4_address || external_ipv4_port.load() != ipv4_port))
		{
			external_ipv4_address.store(ipv4_address);
			external_ipv4_port.store(ipv4_port);
			asio::ip::address address_ipv4 = asio::ip::make_address_v4(ipv4_address);
			std::stringstream ss;
			ss << "External IPv4 Address: " << address_ipv4 << "\n";
			ss << "External IPv4 Port: " << ipv4_port << "\n";
			if (!current_settings.log_ip_address.empty())
				v4_info = ss.str();
			if (!current_settings.update_ipv4_path.empty())
			{
				parallel_pool.submit_detach([update_ipv4_path = current_settings.update_ipv4_path, address_ipv4, ipv4_port]()
					{
						dns_helper::save_ddns_result(update_ipv4_path, address_ipv4, ipv4_port);
					});
			}
		}

		if (ipv6_address != zero_value_array && ipv6_port != 0 && (external_ipv6_address != ipv6_address || external_ipv6_port != ipv6_port))
		{
			external_ipv6_address = ipv6_address;
			external_ipv6_port.store(ipv6_port);
			asio::ip::address address_ipv6 = asio::ip::make_address_v6(ipv6_address);
			std::stringstream ss;
			ss << "External IPv6 Address: " << address_ipv6 << "\n";
			ss << "External IPv6 Port: " << ipv6_port << "\n";
			if (!current_settings.log_ip_address.empty())
				v6_info = ss.str();
			if (!current_settings.update_ipv6_path.empty())
			{
				parallel_pool.submit_detach([update_ipv6_path = current_settings.update_ipv6_path, address_ipv6, ipv4_port]()
					{
						dns_helper::save_ddns_result(update_ipv6_path, address_ipv6, ipv4_port);
					});
			}
		}

		if (!current_settings.log_ip_address.empty())
		{
			std::string message = "Update Time: " + time_to_string() + "\n" + v4_info + v6_info;
			print_ip_to_file(message, current_settings.log_ip_address);
			std::cout << message;
		}
	}

	void server_mode::log_status(const asio::error_code &e)
	{
		if (e == asio::error::operation_aborted)
			return;

		std::string output_text = time_to_string_with_square_brackets() + "Summary of " + current_settings.config_filename + "\n";
		constexpr auto duration_seconds = LOGGING_GAP.count();
		auto listener_receives_raw_traffice = status_counters.ingress_raw_traffic.exchange(0);
		auto listener_receives_raw_traffice_peak = status_counters.ingress_raw_traffic_peak.exchange(0);
		auto listener_receives_raw_traffice_valley = status_counters.ingress_raw_traffic_valley.exchange(0);
		auto listener_send_raw_traffic = status_counters.egress_raw_traffic.exchange(0);
		auto listener_send_raw_traffic_peak = status_counters.egress_raw_traffic_peak.exchange(0);
		auto listener_send_raw_traffic_valley = status_counters.egress_raw_traffic_valley.exchange(0);

		auto listener_receives_raw_speed = to_speed_unit(listener_receives_raw_traffice, duration_seconds);
		auto listener_receives_raw_speed_peak = to_speed_unit(listener_receives_raw_traffice_peak, 1);
		auto listener_receives_raw_speed_valley = to_speed_unit(listener_receives_raw_traffice_valley, 1);
		auto listener_send_raw_speed = to_speed_unit(listener_send_raw_traffic, duration_seconds);
		auto listener_send_raw_speed_peak = to_speed_unit(listener_send_raw_traffic_peak, 1);
		auto listener_send_raw_speed_valley = to_speed_unit(listener_send_raw_traffic_valley, 1);

		auto listener_fec_raw_packets = status_counters.fec_raw_packet_count.exchange(0);
		auto listener_fec_redundants = status_counters.fec_raw_redund_count.exchange(0);
		auto listener_fec_recovery = status_counters.fec_recovery_count.exchange(0);
#ifdef __cpp_lib_format
		output_text += std::format(
			"[This -> Client] avg. {}, max {}, min {}, total {} bytes\n"
			"[Client -> This] avg. {}, max {}, min {}, total {} bytes\n"
			"[This -> Client] Data packets: {}, FEC packets: {}, FEC recoveried: {}\n",
			listener_send_raw_speed, listener_send_raw_speed_peak, listener_send_raw_speed_valley, listener_send_raw_traffic,
			listener_receives_raw_speed, listener_receives_raw_speed_peak, listener_receives_raw_speed_valley, listener_receives_raw_traffice,
			listener_fec_raw_packets, listener_fec_redundants, listener_fec_recovery);
#else
		std::ostringstream oss;
		oss <<
			"[This -> Client] avg." << listener_send_raw_speed << ", max " << listener_send_raw_speed_peak << ", min " << listener_send_raw_speed_valley << ", total " << listener_send_raw_traffic << " bytes\n"
			"[Client -> This] avg. " << listener_receives_raw_speed << ", max " << listener_receives_raw_speed_peak << ", min" << listener_receives_raw_speed_valley << ", total " << listener_receives_raw_traffice << " bytes\n"
			"[Client -> This] Data packets: " << listener_fec_raw_packets << ", FEC packets: " << listener_fec_redundants << ", FEC recoveried: " << listener_fec_recovery << "\n";
		output_text += oss.str();
#endif

		if (!current_settings.log_status.empty())
			print_status_to_file(output_text, current_settings.log_status);
		std::cout << output_text << std::endl;
	
		timer_status_log.expires_after(LOGGING_GAP);
		timer_status_log.async_wait([this](const asio::error_code &e) { log_status(e); });
	}

	void server_mode::peak_valley_traffic(const asio::error_code &e)
	{
		if (e == asio::error::operation_aborted)
			return;

		auto listener_receives_raw_traffice_1s = status_counters.ingress_raw_traffic_each_second.exchange(0);
		auto listener_send_raw_traffic_1s = status_counters.egress_raw_traffic_each_second.exchange(0);

		traffic_pv_counters.ingress_traffic_counter.push_back(listener_receives_raw_traffice_1s);
		traffic_pv_counters.egress_traffic_counter.push_back(listener_send_raw_traffic_1s);

		if (traffic_pv_counters.ingress_traffic_counter.size() >= 60)
		{
			auto [ingress_traffic_min, ingress_traffic_max] = std::ranges::minmax_element(traffic_pv_counters.ingress_traffic_counter);
			auto [egress_traffic_min, egress_traffic_max] = std::ranges::minmax_element(traffic_pv_counters.egress_traffic_counter);
			status_counters.ingress_raw_traffic_peak = *ingress_traffic_max;
			status_counters.ingress_raw_traffic_valley = *ingress_traffic_min;
			status_counters.egress_raw_traffic_peak = *egress_traffic_max;
			status_counters.egress_raw_traffic_valley = *egress_traffic_min;
			traffic_pv_counters.ingress_traffic_counter.clear();
			traffic_pv_counters.egress_traffic_counter.clear();
		}

		timer_peak_valley_traffic.expires_after(std::chrono::seconds(1));
		timer_peak_valley_traffic.async_wait([this](const asio::error_code &e) { peak_valley_traffic(e); });
	}

	asio::awaitable<void> server_mode::detect_startup_errors()
	{
		std::chrono::time_point deadline = std::chrono::steady_clock::now() + FINDER_TIMEOUT_INTERVAL;
		timer_detect_startup_errors.expires_at(deadline);
		co_await timer_detect_startup_errors.async_wait(asio::use_awaitable);

		if (startup_has_error)
			network_io.stop();
	}

	bool server_mode::start()
	{
		std::cout << app_name << " is running as server mode\n";

		fec_enabled = current_settings.fec_original_packet_count > 0 && current_settings.fec_redundant_packet_count > 0;

		uint16_t port_number = current_settings.listen_ports.front();
		if (port_number == 0)
			return false;

		co_spawn(network_io, update_local_udp_target_task(), detached);
		
		if (current_settings.listen_on.empty())
		{
			for (auto port : current_settings.listen_ports)
			{
				switch (current_settings.ip_version_only)
				{
				case ip_only_options::not_set:
					co_spawn(network_io, listener_ipv6_udp(port), detached);
					if constexpr (!linux_system)
						co_spawn(network_io, listener_ipv4_udp(port), detached);
					break;
				case ip_only_options::ipv4:
					co_spawn(network_io, listener_ipv4_udp(port), detached);
					break;
				case ip_only_options::ipv6:
					co_spawn(network_io, listener_ipv6_udp(port), detached);
					break;
				default:
					break;
				}
			}
		}
		else
		{
			asio::error_code ec;
			size_t listen_count = current_settings.listen_on.size();
			std::vector<asio::ip::address_v4> listen_on_ipv4(listen_count);
			std::vector<asio::ip::address_v6> listen_on_ipv6(listen_count);
			listen_on_ipv4.clear();
			listen_on_ipv6.clear();

			for (size_t i = 0; i < listen_count; i++)
			{
				asio::ip::address local_address = asio::ip::make_address(current_settings.listen_on[i], ec);
				if (ec)
				{
					std::string error_message = time_to_string_with_square_brackets() + "Listen Address incorrect - " + current_settings.listen_on[i] + "\n";
					std::cerr << error_message;
					print_message_to_file(error_message, current_settings.log_messages);
					return false;
				}

				if (local_address.is_v4() && current_settings.ip_version_only != ip_only_options::ipv6)
					listen_on_ipv4.emplace_back(local_address.to_v4());

				if (local_address.is_v6() && current_settings.ip_version_only != ip_only_options::ipv4)
					listen_on_ipv6.emplace_back(local_address.to_v6());
			}

			for (auto &ipv4_addrress : listen_on_ipv4)
			{
				for (auto port : current_settings.listen_ports)
				{
					co_spawn(network_io, listener_ipv4_udp(ipv4_addrress, port), detached);
				}
			}
			for (auto &ipv6_addrress : listen_on_ipv6)
			{
				for (auto port : current_settings.listen_ports)
				{
					co_spawn(network_io, listener_ipv6_udp(ipv6_addrress, port), detached);
				}
			}
		}

		co_spawn(network_io, detect_startup_errors(), detached);
		co_spawn(network_io, cleanup_timedout_sessions(), detached);
		
		if (current_settings.keep_alive > 0)
			co_spawn(network_io, session_keep_alive(), detached);

		if (!current_settings.stun_server.empty())
			co_spawn(network_io, send_stun_request(), detached);

		timer_peak_valley_traffic.expires_after(std::chrono::seconds(1));
		timer_peak_valley_traffic.async_wait([this](const asio::error_code &e) { peak_valley_traffic(e); });

		if (!current_settings.log_status.empty())
		{
			timer_status_log.expires_after(LOGGING_GAP);
			timer_status_log.async_wait([this](const asio::error_code &e) { log_status(e); });
		}

		return true;
	}
}
