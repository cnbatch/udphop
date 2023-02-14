#pragma once
#include "connections.hpp"
#include <deque>

#ifndef __CLIENT_HPP__
#define __CLIENT_HPP__

class client_mode
{
	asio::io_context &io_context;
	asio::io_context &network_io;
	user_settings current_settings;
	std::unique_ptr<udp_server> udp_access_point;

	std::shared_mutex mutex_id_map_to_forwarder;
	std::map<uint32_t, std::shared_ptr<forwarder>> id_map_to_forwarder;


	std::shared_mutex mutex_udp_session_map_to_wrapper;
	std::map<udp::endpoint, std::shared_ptr<data_wrapper<forwarder>>> udp_session_map_to_wrapper;
	std::shared_mutex mutex_wrapper_session_map_to_udp;
	std::map<uint32_t, udp::endpoint> wrapper_session_map_to_udp;


	std::mutex mutex_wrapper_channels;
	std::map<uint32_t, std::shared_ptr<data_wrapper<forwarder>>> wrapper_channels;

	std::mutex mutex_expiring_wrapper;
	std::map<uint32_t, std::pair<std::shared_ptr<data_wrapper<forwarder>>, int64_t>> expiring_wrapper;
	std::mutex mutex_expiring_forwarders;
	std::map<std::shared_ptr<forwarder>, int64_t> expiring_forwarders;

	std::shared_mutex mutex_udp_target;
	std::shared_ptr<udp::endpoint> udp_target;
	std::shared_ptr<udp::endpoint> previous_udp_target;

	std::shared_mutex mutex_wrapper_changeport_timestamp;
	std::map<std::shared_ptr<data_wrapper<forwarder>>, std::atomic<int64_t>> wrapper_changeport_timestamp;

	asio::steady_timer timer_find_timeout;
	asio::steady_timer timer_change_ports;
	asio::strand<asio::io_context::executor_type> asio_strand;

	void udp_server_incoming(std::shared_ptr<uint8_t[]> data, size_t data_size, udp::endpoint &&peer, asio::ip::port_type port_number);
	void udp_client_incoming_to_udp(std::shared_ptr<data_wrapper<forwarder>>, std::shared_ptr<uint8_t[]> data, size_t data_size, udp::endpoint &&peer, asio::ip::port_type local_port_number);
	udp::endpoint get_remote_address();

	uint16_t generate_new_port_number(uint16_t start_port_num, uint16_t end_port_num);
	uint32_t generate_token_number();
	void cleanup_expiring_forwarders();
	void cleanup_expiring_data_connections();
	void loop_timeout_sessions();
	void loop_change_new_port();
	void wrapper_loop_updates(const asio::error_code &e);
	void expiring_wrapper_loops(const asio::error_code &e);
	void change_new_port(const asio::error_code &e);

public:
	client_mode() = delete;
	client_mode(const client_mode &) = delete;
	client_mode& operator=(const client_mode &) = delete;

	client_mode(asio::io_context &io_context_ref, asio::io_context &net_io, const user_settings &settings) :
		io_context(io_context_ref),
		network_io(net_io),
		timer_find_timeout(io_context),
		timer_change_ports(io_context),
		asio_strand(asio::make_strand(io_context.get_executor())),
		current_settings(settings) {}

	client_mode(client_mode &&existing_client) noexcept :
		io_context(existing_client.io_context),
		network_io(existing_client.network_io),
		timer_find_timeout(std::move(existing_client.timer_find_timeout)),
		timer_change_ports(std::move(existing_client.timer_change_ports)),
		asio_strand(std::move(existing_client.asio_strand)),
		current_settings(std::move(existing_client.current_settings)) {}
	
	~client_mode();

	bool start();
};

#endif // !__CLIENT_HPP__
