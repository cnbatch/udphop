#include "client.hpp"
#include <asio/experimental/awaitable_operators.hpp>
#include "../shares/data_operations.hpp"
#include "../networks/dns_helper.hpp"

using asio::ip::tcp;
using asio::awaitable;
using asio::co_spawn;
using asio::detached;
using namespace asio::experimental::awaitable_operators;
//using tcp_acceptor = use_awaitable_t<>::as_default_on_t<tcp::acceptor>;
//using tcp_socket = use_awaitable_t<>::as_default_on_t<tcp::socket>;

namespace modes
{
	awaitable<void> client_mode::listener_ipv4_udp(uint16_t port)
	{
		try
		{
			udp::endpoint binding_endpoint(udp::v4(), port);
			udp_socket listener_socket(network_io, binding_endpoint);
			co_spawn(network_io, udp_listener_incoming(std::move(listener_socket)), detached);
		}
		catch (std::exception &e)
		{
			std::cerr << "IPv4 (port " << port << ") udphop_listen Exception: " << e.what() << "\n";
			startup_has_error = true;
		}
		co_return;
	}

	awaitable<void> client_mode::listener_ipv4_udp(asio::ip::address_v4 address, uint16_t port)
	{
		try
		{
			udp::endpoint binding_endpoint(address, port);
			udp_socket listener_socket(network_io, binding_endpoint);
			co_spawn(network_io, udp_listener_incoming(std::move(listener_socket)), detached);
		}
		catch (std::exception &e)
		{
			std::cerr << "IPv4 (" << address << ":" << port <<") udphop_listen Exception: " << e.what() << "\n";
			startup_has_error = true;
		}
		co_return;
	}

	awaitable<void> client_mode::listener_ipv6_udp(uint16_t port)
	{
		try
		{
			udp::endpoint binding_endpoint(udp::v6(), port);
			udp_socket listener_socket(network_io, binding_endpoint);
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

	awaitable<void> client_mode::listener_ipv6_udp(asio::ip::address_v6 address, uint16_t port)
	{
		try
		{
			udp::endpoint binding_endpoint(address, port);
			udp_socket listener_socket(network_io, binding_endpoint);
			co_spawn(network_io, udp_listener_incoming(std::move(listener_socket)), detached);
		}
		catch (std::exception &e)
		{
			std::cerr << "IPv6 ([" << address << "]:" << port << ") udphop_listen Exception: " << e.what() << "\n";
			startup_has_error = true;
		}
		co_return;
	}

	asio::awaitable<void> client_mode::udp_listener_incoming(udp_socket listener_socket)
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

			std::shared_ptr<udp_mappings> udp_session_ptr = nullptr;
			if (auto iter = udp_endpoint_map_to_session.find(from_udp_endpoint);
				iter == udp_endpoint_map_to_session.end())
			{
				co_await udp_listener_incoming_new_connection(data_ptr, bytes_read, from_udp_endpoint, listener_socket);
				continue;
			}
			else udp_session_ptr = iter->second;

			co_spawn(task_context, udp_listener_incoming_existing_connection(std::move(data), data_ptr, bytes_read, listener_socket, udp_session_ptr), detached);
		}
	}

	asio::awaitable<void> client_mode::udp_listener_incoming_new_connection(uint8_t *data, size_t data_size, udp::endpoint peer, udp_socket &listener_socket)
	{
		uint32_t key_number = generate_token_number();
		std::shared_ptr<udp_mappings> udp_session_ptr = std::make_shared<udp_mappings>();
		size_t selected_index = randomly_pick_index(current_settings.destination_address_list.size());
		std::shared_ptr<udp::endpoint> egress_target_endpoint = get_udp_target(selected_index);
		if (egress_target_endpoint == nullptr)
			co_return;

		std::shared_ptr<udp_socket> forwarder_socket = std::make_shared<udp_socket>(network_io);

		udp_session_ptr->egress_target_endpoint = egress_target_endpoint;
		udp_session_ptr->wrapper_ptr = std::make_unique<packet::data_wrapper>(key_number);
		udp_session_ptr->hopping_timestamp.store(right_now() + current_settings.dynamic_port_refresh);
		udp_session_ptr->egress_forwarder = forwarder_socket;
		udp_session_ptr->egress_previous_target_endpoint = std::make_shared<udp::endpoint>(*egress_target_endpoint);
		udp_session_ptr->egress_endpoint_index = selected_index;
		udp_session_ptr->ingress_source_endpoint = std::make_shared<udp::endpoint>(peer);
		udp_session_ptr->ingress_sender.store(&listener_socket);

		packet::data_wrapper *data_wrapper_ptr = udp_session_ptr->wrapper_ptr.get();
		auto [packed_data, packed_data_size] = data_wrapper_ptr->prepend_header(feature::raw_data, data, data_size);
		auto [error_message, cipher_size] = co_await cipher_operations.async_encrypt(network_io, packed_data, (int)packed_data_size);
		if (!error_message.empty() || cipher_size == 0)
			co_return;

		udp_session_channels[key_number] = udp_session_ptr;
		udp_endpoint_map_to_session[peer] = udp_session_ptr;

		if (fec_enabled)
		{
			size_t K = current_settings.fec_original_packet_count;
			size_t N = K + current_settings.fec_redundant_packet_count;
			udp_session_ptr->fec_egress_control.fecc.reset_martix(K, N);
		}

		asio::error_code ec;
		if (egress_target_endpoint->address().is_v4())
			forwarder_socket->open(udp::v4(), ec);
		if (egress_target_endpoint->address().is_v6())
			forwarder_socket->open(udp::v6(), ec);

		if (!ec)
			co_await forwarder_socket->async_send_to(asio::buffer(packed_data, cipher_size), *egress_target_endpoint, asio::redirect_error(asio::use_awaitable, ec));

		if (ec)
		{
			if (auto iter = udp_session_channels.find(key_number); iter != udp_session_channels.end())
				udp_session_channels.erase(iter);
			if (auto iter = udp_endpoint_map_to_session.find(peer); iter != udp_endpoint_map_to_session.end())
				udp_endpoint_map_to_session.erase(iter);
		}
		else
		{
			status_counters.egress_raw_traffic += cipher_size;
			status_counters.egress_raw_traffic_each_second += cipher_size;
			udp_session_ptr->last_ingress_receive_time.store(right_now());
			udp_session_ptr->last_ingress_send_time.store(right_now());
			udp_session_ptr->last_egress_receive_time.store(right_now());
			udp_session_ptr->last_egress_send_time.store(right_now());
			co_spawn(network_io, udp_forwarder_incoming_to_udp(udp_session_ptr, forwarder_socket), detached);
		}
	}

	asio::awaitable<void> client_mode::udp_listener_incoming_existing_connection(std::unique_ptr<uint8_t[]> original_cache, uint8_t *data, size_t data_size, udp_socket &listener_socket, std::shared_ptr<udp_mappings> udp_session_ptr)
	{
		if (!listener_socket.is_open())
			co_return;

		asio::error_code ec;
		std::shared_ptr<udp_socket> egress_forwarder = load_atomic_ptr(udp_session_ptr->egress_forwarder);
		std::shared_ptr<udp::endpoint> egress_target_endpoint = load_atomic_ptr(udp_session_ptr->egress_target_endpoint);
		if (egress_forwarder == nullptr || egress_target_endpoint == nullptr)
			co_return;
		if (fec_enabled)
		{
			fec_maker(udp_session_ptr, std::move(original_cache), data, data_size);
		}
		else
		{
			auto [packed_data, packed_data_size] = udp_session_ptr->wrapper_ptr->prepend_header(feature::raw_data, data, data_size);
			auto [error_message, cipher_size] = co_await cipher_operations.async_encrypt(task_context, packed_data, (int)packed_data_size);
			if (!error_message.empty() || cipher_size == 0)
				co_return;
			co_await egress_forwarder->async_send_to(asio::buffer(packed_data, cipher_size), *egress_target_endpoint, asio::redirect_error(asio::use_awaitable, ec));
		}

		udp_session_ptr->last_ingress_receive_time.store(right_now());
		udp_session_ptr->last_egress_send_time.store(right_now());
		inspect_change_port_status(udp_session_ptr, egress_forwarder);
	}

	std::unique_ptr<udp::endpoint> client_mode::get_udp_target(size_t index)
	{
		std::shared_ptr<asio::ip::address> target = load_atomic_ptr(target_address[index]);
		if (target != nullptr)
		{
			uint16_t destination_port = current_settings.destination_ports.front();
			if (current_settings.destination_ports.size() > 0)
				destination_port = generate_new_port_number(current_settings.destination_ports);

			return std::make_unique<udp::endpoint>(*target, destination_port);
		}

		return update_udp_target(index);
	}

	std::unique_ptr<udp::endpoint> client_mode::update_udp_target(size_t index)
	{
		uint16_t destination_port = current_settings.destination_ports.front();
		if (current_settings.destination_ports.size() > 0)
			destination_port = generate_new_port_number(current_settings.destination_ports);

		asio::error_code ec;
		std::unique_ptr<udp::endpoint> udp_target;
		udp::resolver resolver(network_io);
		for (int i = 0; i <= RETRY_TIMES; ++i)
		{
			const std::string &destination_address = current_settings.destination_address_list[index];
			udp::resolver::results_type udp_endpoints = resolver.resolve(destination_address, "", ec);
			if (ec)
			{
				std::string error_message = time_to_string_with_square_brackets() + ec.message() + "\n";
				std::cerr << error_message << "\n";
				print_message_to_file(error_message, current_settings.log_messages);
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
				std::atomic_store(&target_address[index], std::make_shared<asio::ip::address>(udp_target->address()));
				break;
			}
		}

		return std::move(udp_target);
	}

	asio::awaitable<void> client_mode::update_udp_target_task(size_t index, asio::steady_timer timer)
	{
		asio::error_code ec;
		udp::resolver resolver(network_io);
		for (int i = 0; i <= RETRY_TIMES; ++i)
		{
			const std::string &destination_address = current_settings.destination_address_list[index];
			udp::resolver::results_type udp_endpoints = co_await resolver.async_resolve(destination_address, "", asio::redirect_error(asio::use_awaitable, ec));
			std::chrono::time_point deadline = std::chrono::steady_clock::now() + FINDER_TIMEOUT_INTERVAL;
			if (ec)
			{
				std::string error_message = time_to_string_with_square_brackets() + ec.message() + "\n";
				std::cerr << error_message << "\n";
				print_message_to_file(error_message, current_settings.log_messages);
				timer.expires_at(deadline);
				co_await timer.async_wait(asio::use_awaitable);
			}
			else if (udp_endpoints.size() == 0)
			{
				std::string error_message = time_to_string_with_square_brackets() + "destination address not found\n";
				std::cerr << error_message << "\n";
				print_message_to_file(error_message, current_settings.log_messages);
				timer.expires_at(deadline);
				co_await timer.async_wait(asio::use_awaitable);
			}
			else
			{
				udp::endpoint target_endpoint = *udp_endpoints.begin();
				std::atomic_store(&target_address[index], std::make_shared<asio::ip::address>(target_endpoint.address()));
				break;
			}
		}
		timer.expires_at(std::chrono::steady_clock::now() + std::chrono::seconds(RETRY_TIMES));
		co_await timer.async_wait(asio::use_awaitable);
		co_spawn(network_io, update_udp_target_task(index, std::move(timer)), detached);
	}

	asio::awaitable<void> client_mode::update_dnstxt_task(asio::steady_timer timer)
	{
		timer.expires_at(std::chrono::steady_clock::now() + std::chrono::seconds(RETRY_TIMES));
		co_await timer.async_wait(asio::use_awaitable);
		
		std::vector<std::string> error_msg;
		std::string &destination_dnstxt = current_settings.destination_dnstxt;

		auto async_update = [this, &destination_dnstxt, &error_msg](auto &&handler) mutable
			{
				std::shared_ptr handler_pair = std::make_shared<std::remove_cvref_t<decltype(handler)>>(std::move(handler));
				parallel_pool.submit_detach([this, &destination_dnstxt, &error_msg, handler_pair]() mutable
					{
						auto output_data = dns_helper::query_dns_txt(destination_dnstxt, error_msg);
						auto handler = std::move(*handler_pair.get());
						asio::post(network_io, [output_data = std::move(output_data), handler = std::move(handler)]() mutable
							{
								handler(std::move(output_data));
							});
					});
			};
		std::string dnstxt_content = co_await asio::async_initiate<decltype(asio::use_awaitable), void(std::string)>(async_update, asio::use_awaitable);
		if (error_msg.empty())
		{
			auto [host_address, ip_address, port_num] = dns_helper::dns_split_address(dnstxt_content, error_msg);

			if (error_msg.empty())
			{
				current_settings.destination_ports.resize(1);
				current_settings.destination_ports.front() = port_num;
				target_address.resize(1);
				target_address.front() = std::make_shared<asio::ip::address>(ip_address);
			}
			else
			{
				if (!host_address.empty() && port_num != 0)
				{
					current_settings.destination_address_list.resize(1);
					current_settings.destination_address_list.front() = host_address;
					current_settings.destination_ports.resize(1);
					current_settings.destination_ports.front() = port_num;
				}
			}
		}
		else
		{
			for (auto &msg : error_msg)
			{
				std::cerr << msg << "\n";
			}
		}
		co_spawn(network_io, update_dnstxt_task(std::move(timer)), detached);
	}

	asio::awaitable<void> client_mode::udp_forwarder_incoming_to_udp(std::shared_ptr<udp_mappings> udp_session_ptr, std::shared_ptr<udp_socket> forwarder_socket)
	{
		udp::endpoint remote_udp_endpoint;
		asio::error_code ec;

		while (forwarder_socket->is_open())
		{
			std::unique_ptr<uint8_t[]> data = std::make_unique_for_overwrite<uint8_t[]>(BUFFER_SIZE + BUFFER_EXPAND_SIZE);
			uint8_t *data_ptr = data.get();
			size_t bytes_read = co_await forwarder_socket->async_receive_from(asio::buffer(data_ptr, BUFFER_SIZE), remote_udp_endpoint, asio::redirect_error(asio::use_awaitable, ec));
			std::shared_ptr<udp::endpoint> ingress_source_endpoint = load_atomic_ptr(udp_session_ptr->ingress_source_endpoint);
			if (ec)
			{
				uint32_t key_number = udp_session_ptr->wrapper_ptr->get_iden();
				if (auto iter = udp_session_channels.find(key_number); iter != udp_session_channels.end())
					udp_session_channels.erase(iter);
				if (auto iter = udp_endpoint_map_to_session.find(*ingress_source_endpoint); iter != udp_endpoint_map_to_session.end())
					udp_endpoint_map_to_session.erase(iter);
				break;
			}

			if (bytes_read == 0)
				continue;

			if (bytes_read < RAW_HEADER_SIZE)
				continue;

			status_counters.ingress_raw_traffic += bytes_read;
			status_counters.ingress_raw_traffic_each_second += bytes_read;
			co_spawn(task_context, udp_forwarder_incoming_to_udp_unpack(udp_session_ptr, forwarder_socket, std::move(data), data_ptr, bytes_read, remote_udp_endpoint), detached);
		}

		for (auto iter = udp_endpoint_map_to_session.begin(), next = iter; iter != udp_endpoint_map_to_session.end(); iter = next)
		{
			next++;
			if (iter->second != udp_session_ptr)
				continue;
			udp_endpoint_map_to_session.erase(iter);
			udp_session_ptr->egress_forwarder = nullptr;
		}
		udp_session_channels.erase(udp_session_ptr->wrapper_ptr->get_iden());
	}

	asio::awaitable<void> client_mode::udp_forwarder_incoming_to_udp_unpack(std::shared_ptr<udp_mappings> udp_session_ptr, std::shared_ptr<udp_socket> forwarder_socket, std::unique_ptr<uint8_t[]> original_cache, uint8_t *data_ptr, size_t data_size, udp::endpoint remote_udp_endpoint)
	{
		if (!forwarder_socket->is_open())
			co_return;

		auto [error_message, plain_size] = co_await cipher_operations.async_decrypt(task_context,data_ptr, (int)data_size);
		if (!error_message.empty() || plain_size == 0)
			co_return;

		auto [packet_timestamp, feature_value, received_data_ptr, received_size] = udp_session_ptr->wrapper_ptr->receive_data(data_ptr, plain_size);
		if (received_size == 0 || packet_timestamp == 0 || feature_value == feature::test_connection)
			co_return;

		auto timestamp = right_now();
		if (calculate_difference<int64_t>((uint32_t)timestamp, packet_timestamp) > TIME_GAP)
			co_return;

		std::shared_ptr<udp::endpoint> egress_target_endpoint = load_atomic_ptr(udp_session_ptr->egress_target_endpoint);
		std::shared_ptr<udp::endpoint> egress_previous_target_endpoint = load_atomic_ptr(udp_session_ptr->egress_previous_target_endpoint);
		if (*egress_target_endpoint != remote_udp_endpoint && *egress_previous_target_endpoint != remote_udp_endpoint)
		{
			std::atomic_store(&(udp_session_ptr->egress_previous_target_endpoint), egress_target_endpoint);
			std::atomic_store(&(udp_session_ptr->egress_target_endpoint), std::make_shared<udp::endpoint>(remote_udp_endpoint));
			std::atomic_store(&(target_address[udp_session_ptr->egress_endpoint_index]), std::make_shared<asio::ip::address>(remote_udp_endpoint.address()));
		}

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
			co_await forwarder_socket->async_send_to(asio::buffer(response_packet_ptr, cipher_size), remote_udp_endpoint, asio::redirect_error(asio::use_awaitable, ec));
			break;
		}
		case feature::keep_alive_response:
			break;
		case feature::test_connection:
			break;
		case feature::raw_data:
		{
			if (fec_enabled)
			{
				auto [fec_data_ptr, fec_data_size] = fec_unpack(udp_session_ptr, data_ptr, plain_size);
				if (fec_data_ptr == nullptr)
					break;
				received_data_ptr = fec_data_ptr;
				received_size = fec_data_size;
			}
			std::shared_ptr<udp::endpoint> ingress_source_endpoint = load_atomic_ptr(udp_session_ptr->ingress_source_endpoint);
			co_await udp_session_ptr->ingress_sender.load()->async_send_to(asio::buffer(received_data_ptr, received_size), *ingress_source_endpoint, asio::redirect_error(asio::use_awaitable, ec));
			udp_session_ptr->last_egress_receive_time.store(right_now());
			udp_session_ptr->last_ingress_send_time.store(right_now());
			break;
		}
		default:
			break;
		}
		inspect_change_port_status(udp_session_ptr, forwarder_socket);
	}

	void client_mode::fec_maker(std::shared_ptr<udp_mappings> udp_session_ptr, std::unique_ptr<uint8_t[]> original_cache, uint8_t *data, size_t data_size)
	{
		fec_control_data &fec_controllor = udp_session_ptr->fec_egress_control;
		if (data != nullptr && data_size > 0)
		{
			fec_controllor.fec_snd_cache.emplace_back(clone_into_pair(data, data_size));
			auto [packed_data, packed_data_size] = udp_session_ptr->wrapper_ptr->prepend_header_fec(feature::raw_data, data, data_size, fec_controllor.fec_snd_sn.load(), fec_controllor.fec_snd_sub_sn++);

			std::shared_ptr<uint8_t[]> original_cache_sp = std::move(original_cache);
			parallel_pool.submit_detach([this, udp_session_ptr, original_cache_sp, packed_data, packed_data_size]() mutable
				{
					std::shared_ptr<udp_socket> egress_forwarder = load_atomic_ptr(udp_session_ptr->egress_forwarder);
					std::shared_ptr<udp::endpoint> egress_target_endpoint = load_atomic_ptr(udp_session_ptr->egress_target_endpoint);
					if (egress_forwarder == nullptr || egress_target_endpoint == nullptr)
						return;
					auto [error_message, cipher_size] = encrypt_data(current_settings.encryption_password, current_settings.encryption, packed_data, (int)packed_data_size);
					if (!error_message.empty() || cipher_size == 0)
						return;
					auto asio_buffer = asio::buffer(packed_data, cipher_size);
					egress_forwarder->async_send_to(asio_buffer, *egress_target_endpoint, [original_cache_sp](auto, auto) {});
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
						std::shared_ptr<udp_socket> egress_forwarder = load_atomic_ptr(udp_session_ptr->egress_forwarder);
						std::shared_ptr<udp::endpoint> egress_target_endpoint = load_atomic_ptr(udp_session_ptr->egress_target_endpoint);
						if (egress_forwarder == nullptr || egress_target_endpoint == nullptr)
							return;
						auto [error_message, cipher_size] = encrypt_data(current_settings.encryption_password, current_settings.encryption, fec_redundant_buffer_sp.get(), (int)fec_redundant_buffer_size);
						if (!error_message.empty() || cipher_size == 0)
							return;
						auto asio_buffer = asio::buffer(fec_redundant_buffer_sp.get(), cipher_size);
						egress_forwarder->async_send_to(asio_buffer, *egress_target_endpoint, [fec_redundant_buffer_sp](auto, auto) {});
						status_counters.egress_raw_traffic += cipher_size;
						status_counters.egress_raw_traffic_each_second += cipher_size;
					});
			}
			fec_controllor.fec_snd_cache.clear();
			fec_controllor.fec_snd_sub_sn.store(0);
			fec_controllor.fec_snd_sn++;
		}
	}

	std::pair<uint8_t *, size_t> client_mode::fec_unpack(std::shared_ptr<udp_mappings> &udp_session_ptr, uint8_t *original_data_ptr, size_t plain_size)
	{
		uint8_t *data_ptr = nullptr;
		size_t packet_data_size = 0;
		auto [packet_header, fec_data_ptr, fec_data_size] = udp_session_ptr->wrapper_ptr->receive_data_with_fec(original_data_ptr, plain_size);
		uint32_t fec_sn = packet_header.sn;
		uint8_t fec_sub_sn = packet_header.sub_sn;

		std::pair<std::unique_ptr<uint8_t[]>, size_t> &original_data_clone = udp_session_ptr->fec_egress_control.fec_rcv_cache[fec_sn][fec_sub_sn];
		original_data_clone.first = std::make_unique_for_overwrite<uint8_t[]>(fec_data_size);
		original_data_clone.second = fec_data_size;
		std::copy_n(fec_data_ptr, fec_data_size, original_data_clone.first.get());
		fec_find_missings(udp_session_ptr.get(), udp_session_ptr->fec_egress_control, fec_sn, current_settings.fec_original_packet_count);

		if (packet_header.sub_sn < current_settings.fec_original_packet_count)
		{
			data_ptr = fec_data_ptr;
			packet_data_size = fec_data_size;
			status_counters.fec_raw_packet_count++;
		}
		else status_counters.fec_raw_redund_count++;

		return { data_ptr, packet_data_size };
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
				std::shared_ptr<udp::endpoint> udp_endpoint = load_atomic_ptr(udp_session_ptr->ingress_source_endpoint);
				udp_session_ptr->ingress_sender.load()->async_send_to(asio::buffer(missed_data_ptr, missed_data_size), *udp_endpoint,
					[data_ = std::move(data)](const asio::error_code &error, size_t bytes_transferred) {});
				status_counters.fec_recovery_count++;
			}

			fec_controllor.fec_rcv_restored.insert(sn);
		}
	}

	void client_mode::inspect_change_port_status(std::shared_ptr<udp_mappings> udp_mappings_ptr, std::shared_ptr<udp_socket> forwarder_socket)
	{
		if (udp_mappings_ptr->hopping_timestamp.load() > right_now() || forwarder_socket == nullptr || !forwarder_socket->is_open())
			return;
		udp_mappings_ptr->hopping_timestamp.store(LLONG_MAX);
		co_spawn(network_io, change_new_port(udp_mappings_ptr, forwarder_socket), detached);
	}

	asio::awaitable<void> client_mode::change_new_port(std::shared_ptr<udp_mappings> udp_mappings_ptr, std::shared_ptr<udp_socket> forwarder_socket)
	{
		auto time_right_now = right_now();
		const std::vector<uint16_t> &destination_ports = current_settings.destination_ports;
		const std::vector<std::string> &destination_address_list = current_settings.destination_address_list;
		asio::error_code ec;

		try
		{
			std::shared_ptr<udp_socket> forwarder_new_socket = std::make_shared<udp_socket>(network_io);
			bool endpoint_changed = false;
			std::shared_ptr<udp::endpoint> egress_target_endpoint = load_atomic_ptr(udp_mappings_ptr->egress_target_endpoint);
			std::shared_ptr<udp::endpoint> egress_target_new_endpoint;
			if (destination_address_list.size() > 1)
			{
				size_t selected_index = randomly_pick_index(destination_address_list.size());
				egress_target_new_endpoint = get_udp_target(selected_index);
				if (egress_target_new_endpoint == nullptr)
				{
					endpoint_changed = false;
				}
				else
				{
					udp_mappings_ptr->egress_endpoint_index = selected_index;
					endpoint_changed = true;
				}
			}
			else if (destination_ports.size() > 1)
			{
				uint16_t current_port_number = egress_target_endpoint->port();
				uint16_t new_port_numer = generate_new_port_number(destination_ports);
				for (size_t retry_times = 0; new_port_numer == current_port_number && retry_times < RETRY_TIMES; retry_times++)
				{
					new_port_numer = generate_new_port_number(destination_ports);
				}
				egress_target_new_endpoint = std::make_shared<udp::endpoint>(*egress_target_endpoint);
				egress_target_new_endpoint->port(new_port_numer);
				endpoint_changed = true;
			}

			if (egress_target_new_endpoint == nullptr)
				endpoint_changed = false;

			packet::data_wrapper wrapper(0);
			auto [test_packet, test_packet_size] = wrapper.create_test_connection_packet();
			if (egress_target_new_endpoint->address().is_v4())
				forwarder_new_socket->open(udp::v4(), ec);
			if (egress_target_new_endpoint->address().is_v6())
				forwarder_new_socket->open(udp::v6(), ec);
			if (!ec)
			{
				auto [error_message, cipher_size] = co_await cipher_operations.async_encrypt(network_io, test_packet.get(), (int)test_packet_size);
				if (!error_message.empty() || cipher_size == 0)
					co_return;
				co_await forwarder_new_socket->async_send_to(asio::buffer(test_packet.get(), cipher_size), *egress_target_new_endpoint, asio::redirect_error(asio::use_awaitable, ec));
			}
			if (ec || !forwarder_socket->is_open())
			{
				udp_mappings_ptr->hopping_timestamp.store(time_right_now + current_settings.dynamic_port_refresh);
				co_return;
			}

			bool success = false;
			for (int i = 0; i < RETRY_TIMES && !success; i++)
			{
				co_await(test_before_change(wrapper, forwarder_new_socket, success) || watchdog_test_change());
				if (!success)
				{
					auto [test_packet, test_packet_size] = wrapper.create_test_connection_packet();
					auto [error_message, cipher_size] = co_await cipher_operations.async_encrypt(network_io, test_packet.get(), (int)test_packet_size);
					if (!error_message.empty() || cipher_size == 0)
						continue;
					co_await forwarder_new_socket->async_send_to(asio::buffer(test_packet.get(), cipher_size), *egress_target_new_endpoint, asio::redirect_error(asio::use_awaitable, ec));
				}
			}

			if (!success)
			{
				udp_mappings_ptr->hopping_timestamp.store(time_right_now + current_settings.dynamic_port_refresh);
				co_return;
			}

			if (!forwarder_socket->is_open())
			{
				success = false;
				udp_mappings_ptr->hopping_timestamp.store(time_right_now + current_settings.dynamic_port_refresh);
				co_return;
			}

			if (endpoint_changed)
				udp_mappings_ptr->egress_target_endpoint = egress_target_new_endpoint;
			udp_mappings_ptr->egress_forwarder = forwarder_new_socket;
			co_spawn(network_io, udp_forwarder_incoming_to_udp(udp_mappings_ptr, forwarder_new_socket), detached);
			co_spawn(network_io, close_old_socket(forwarder_socket), detached);
		}
		catch (std::exception &ex)
		{
			std::string error_message = time_to_string_with_square_brackets() + "Cannot switch to new port, error: " + ex.what() + "\n";
			std::cerr << error_message;
			print_message_to_file(error_message, current_settings.log_messages);
		}
		udp_mappings_ptr->hopping_timestamp.store(time_right_now + current_settings.dynamic_port_refresh);
	}

	asio::awaitable<void> client_mode::test_before_change(packet::data_wrapper &wrapper, std::shared_ptr<udp_socket> forwarder_socket, bool &success)
	{
		success = false;
		asio::error_code ec;
		std::unique_ptr<uint8_t[]> data = std::make_unique_for_overwrite<uint8_t[]>(BUFFER_SIZE + BUFFER_EXPAND_SIZE);
		uint8_t *data_ptr = data.get();
		udp::endpoint from_udp_endpoint;
		size_t bytes_read = co_await forwarder_socket->async_receive_from(asio::buffer(data_ptr, BUFFER_SIZE), from_udp_endpoint, asio::redirect_error(asio::use_awaitable, ec));

		if (bytes_read == 0)
			co_return;

		if (bytes_read < RAW_HEADER_SIZE)
			co_return;

		auto [error_message, plain_size] = co_await cipher_operations.async_decrypt(network_io,data_ptr, (int)bytes_read);
		if (!error_message.empty() || plain_size == 0)
			co_return;

		auto [packet_timestamp, feature_value, received_data_ptr, received_size] = wrapper.receive_data(data_ptr, plain_size);
		if (received_size == 0 || packet_timestamp == 0)
			co_return;

		auto timestamp = right_now();
		if (calculate_difference<int64_t>((uint32_t)timestamp, packet_timestamp) > TIME_GAP)
			co_return;

		switch (feature_value)
		{
		case feature::keep_alive_response:
			[[fallthrough]];
		case feature::test_connection:
			success = true;
			break;
		default:
			break;
		}
	}

	asio::awaitable<void> client_mode::watchdog_test_change()
	{
		asio::steady_timer timer(network_io);
		std::chrono::time_point deadline = std::chrono::steady_clock::now() + CHANGEPORT_UPDATE_INTERVAL;
		timer.expires_at(deadline);
		co_await timer.async_wait(asio::use_awaitable);
	}

	asio::awaitable<void> client_mode::close_old_socket(std::shared_ptr<udp_socket> forwarder_socket)
	{
		asio::steady_timer timer(network_io);
		std::chrono::time_point deadline = std::chrono::steady_clock::now() + EXPRING_UPDATE_INTERVAL;
		timer.expires_at(deadline);
		co_await timer.async_wait(asio::use_awaitable);
		forwarder_socket->close();
	}

	asio::awaitable<void> client_mode::cleanup_timedout_sessions()
	{
		std::chrono::time_point deadline = std::chrono::steady_clock::now() + FINDER_TIMEOUT_INTERVAL;
		timer_find_timeout.expires_at(deadline);
		co_await timer_find_timeout.async_wait(asio::use_awaitable);

		for (auto iter = udp_endpoint_map_to_session.begin(), next = iter; iter != udp_endpoint_map_to_session.end(); iter = next)
		{
			next++;
			std::shared_ptr<udp_mappings> udp_session_ptr = iter->second;
			std::shared_ptr<udp_socket> egress_forwarder = load_atomic_ptr(udp_session_ptr->egress_forwarder);
			if (time_gap_of_ingress_receive(udp_session_ptr.get()) > current_settings.timeout ||
				time_gap_of_ingress_send(udp_session_ptr.get()) > current_settings.timeout)
			{
				udp_session_ptr->egress_forwarder = nullptr;
				udp_endpoint_map_to_session.erase(iter);
				udp_session_channels.erase(udp_session_ptr->wrapper_ptr->get_iden());
				if (egress_forwarder != nullptr)
					egress_forwarder->close();
			}
			else if (time_gap_of_egress_receive(udp_session_ptr.get()) > DEAD_LINK_TIMES_UP ||
			         time_gap_of_egress_send(udp_session_ptr.get()) > DEAD_LINK_TIMES_UP)
			{
				if (udp_session_ptr->hopping_timestamp.load() == LLONG_MAX || egress_forwarder == nullptr || !egress_forwarder->is_open())
					continue;
				udp_session_ptr->hopping_timestamp.store(LLONG_MAX);
				co_spawn(network_io, change_new_port(udp_session_ptr, egress_forwarder), detached);
			}
		}

		co_spawn(network_io, cleanup_timedout_sessions(), detached);
	}

	asio::awaitable<void> client_mode::session_keep_alive()
	{
		std::chrono::time_point deadline = std::chrono::steady_clock::now() + FINDER_TIMEOUT_INTERVAL;
		timer_keep_alive.expires_at(deadline);
		co_await timer_keep_alive.async_wait(asio::use_awaitable);
		
		for (auto &[iden, udp_session_ptr] : udp_session_channels)
		{
			if (udp_session_ptr->keep_alive_egress_timestamp.load() < right_now())
				continue;

			parallel_pool.submit_detach([this, udp_session_ptr]()
				{
					std::shared_ptr<udp::endpoint> egress_target_endpoint = load_atomic_ptr(udp_session_ptr->egress_target_endpoint);
					std::shared_ptr<udp_socket> egress_forwarder = load_atomic_ptr(udp_session_ptr->egress_forwarder);
					if (egress_forwarder == nullptr || egress_target_endpoint == nullptr)
						return;
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
					egress_forwarder->async_send_to(asio_buffer, *egress_target_endpoint, [data_ = std::move(cache_array)](auto, auto) {});
					udp_session_ptr->keep_alive_egress_timestamp += current_settings.keep_alive;
				});
		}

		co_spawn(network_io, session_keep_alive(), detached);
	}

	void client_mode::log_status(const asio::error_code &e)
	{
		if (e == asio::error::operation_aborted)
			return;

		std::string output_text = time_to_string_with_square_brackets() + "Summary of " + current_settings.config_filename + "\n";
		constexpr auto duration_seconds = LOGGING_GAP.count();
		auto forwarder_receives_raw_traffice = status_counters.ingress_raw_traffic.exchange(0);
		auto forwarder_receives_raw_traffice_peak = status_counters.ingress_raw_traffic_peak.exchange(0);
		auto forwarder_receives_raw_traffice_valley = status_counters.ingress_raw_traffic_valley.exchange(0);
		auto forwarder_send_raw_traffic = status_counters.egress_raw_traffic.exchange(0);
		auto forwarder_send_raw_traffic_peak = status_counters.egress_raw_traffic_peak.exchange(0);
		auto forwarder_send_raw_traffic_valley = status_counters.egress_raw_traffic_valley.exchange(0);
		
		auto forwarder_receives_raw_speed = to_speed_unit(forwarder_receives_raw_traffice, duration_seconds);
		auto forwarder_receives_raw_speed_peak = to_speed_unit(forwarder_receives_raw_traffice_peak, 1);
		auto forwarder_receives_raw_speed_valley = to_speed_unit(forwarder_receives_raw_traffice_valley, 1);
		auto forwarder_send_raw_speed = to_speed_unit(forwarder_send_raw_traffic, duration_seconds);
		auto forwarder_send_raw_speed_peak = to_speed_unit(forwarder_send_raw_traffic_peak, 1);
		auto forwarder_send_raw_speed_valley = to_speed_unit(forwarder_send_raw_traffic_valley, 1);
		
		auto forwarder_fec_raw_packets = status_counters.fec_raw_packet_count.exchange(0);
		auto forwarder_fec_redundants = status_counters.fec_raw_redund_count.exchange(0);
		auto forwarder_fec_recovery = status_counters.fec_recovery_count.exchange(0);
#ifdef __cpp_lib_format
		output_text += std::format(
			"[This -> Server] avg. {}, max {}, min {}, total {} bytes\n"
			"[Server -> This] avg. {}, max {}, min {}, total {} bytes\n"
			"[Server -> This] Data packets: {}, FEC packets: {}, FEC recoveried: {}\n",
			forwarder_send_raw_speed, forwarder_send_raw_speed_peak, forwarder_send_raw_speed_valley, forwarder_send_raw_traffic,
			forwarder_receives_raw_speed, forwarder_receives_raw_speed_peak, forwarder_receives_raw_speed_valley, forwarder_receives_raw_traffice,
			forwarder_fec_raw_packets, forwarder_fec_redundants, forwarder_fec_recovery);
#else
		std::ostringstream oss;
		oss <<
			"[This -> Server] avg." << forwarder_send_raw_speed << ", max " << forwarder_send_raw_speed_peak << ", min " << forwarder_send_raw_speed_valley << ", total " << forwarder_send_raw_traffic << " bytes\n"
			"[Server -> This] avg. " << forwarder_receives_raw_speed << ", max " << forwarder_receives_raw_speed_peak << ", min" << forwarder_receives_raw_speed_valley << ", total " << forwarder_receives_raw_traffice << " bytes\n"
			"[Server -> This] Data packets: " << forwarder_fec_raw_packets << ", FEC packets: " << forwarder_fec_redundants << ", FEC recoveried: " << forwarder_fec_recovery << "\n";
		output_text += oss.str();
#endif

		if (!current_settings.log_status.empty())
			print_status_to_file(output_text, current_settings.log_status);
		std::cout << output_text << std::endl;

		timer_status_log.expires_after(LOGGING_GAP);
		timer_status_log.async_wait([this](const asio::error_code &e) { log_status(e); });
	}

	void client_mode::peak_valley_traffic(const asio::error_code &e)
	{
		if (e == asio::error::operation_aborted)
			return;

		auto forwarder_receives_raw_traffice_1s = status_counters.ingress_raw_traffic_each_second.exchange(0);
		auto forwarder_send_raw_traffic_1s = status_counters.egress_raw_traffic_each_second.exchange(0);

		traffic_pv_counters.ingress_traffic_counter.push_back(forwarder_receives_raw_traffice_1s);
		traffic_pv_counters.egress_traffic_counter.push_back(forwarder_send_raw_traffic_1s);

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

	asio::awaitable<void> client_mode::detect_startup_errors()
	{
		auto executor = co_await asio::this_coro::executor;
		std::chrono::time_point deadline = std::chrono::steady_clock::now() + FINDER_TIMEOUT_INTERVAL;
		timer_detect_startup_errors.expires_at(deadline);
		co_await timer_detect_startup_errors.async_wait(asio::use_awaitable);

		if (startup_has_error)
		{
			network_io.stop();
			task_context.stop();
		}
	}

	bool client_mode::start()
	{
		std::cout << app_name << " is running as client mode\n";

		fec_enabled = current_settings.fec_original_packet_count > 0 && current_settings.fec_redundant_packet_count > 0;

		uint16_t port_number = current_settings.listen_ports.front();
		if (port_number == 0)
			return false;

		if (current_settings.destination_dnstxt.empty())
		{
			target_address.resize(current_settings.destination_address_list.size());
			for (size_t i = 0; i < current_settings.destination_address_list.size(); i++)
			{
				asio::steady_timer timer(network_io);
				co_spawn(network_io, update_udp_target_task(i, std::move(timer)), detached);
			}
		}
		else
		{
			std::vector<std::string> error_msg;
			std::string dnstxt_content = dns_helper::query_dns_txt(current_settings.destination_dnstxt, error_msg);
			if (!error_msg.empty())
			{
				for (auto &msg : error_msg)
				{
					std::cerr << msg << "\n";
				}
				return false;
			}

			auto [host_address, ip_address, port_num] = dns_helper::dns_split_address(dnstxt_content, error_msg);

			if (error_msg.empty())
			{
				current_settings.destination_address_list.resize(1);
				current_settings.destination_address_list.front() = ip_address.to_string();
				current_settings.destination_ports.resize(1);
				current_settings.destination_ports.front() = port_num;
				target_address.resize(1);
				target_address.front() = std::make_shared<asio::ip::address>(ip_address);
			}
			else
			{
				if (host_address.empty() || port_num == 0)
				{
					for (auto &msg : error_msg)
					{
						std::cerr << msg << "\n";
					}
					return false;
				}

				current_settings.destination_address_list.resize(1);
				current_settings.destination_address_list.front() = host_address;
				current_settings.destination_ports.resize(1);
				current_settings.destination_ports.front() = port_num;
				target_address.resize(1);

				asio::steady_timer timer(network_io);
				co_spawn(network_io, update_udp_target_task(0, std::move(timer)), detached);
			}
	
			asio::steady_timer timer(network_io);
			co_spawn(network_io, update_dnstxt_task(std::move(timer)), detached);
		}

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
