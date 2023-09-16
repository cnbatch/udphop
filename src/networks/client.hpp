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

	std::shared_mutex mutex_udp_endpoint_map_to_session;
	std::map<udp::endpoint, std::shared_ptr<udp_mappings>> udp_endpoint_map_to_session;

	std::shared_mutex mutex_udp_session_channels;
	std::map<uint32_t, std::shared_ptr<udp_mappings>> udp_session_channels;

	std::mutex mutex_expiring_sessions;
	std::map<std::shared_ptr<udp_mappings>, int64_t, std::owner_less<>> expiring_sessions;
	std::mutex mutex_expiring_forwarders;
	std::map<std::shared_ptr<forwarder>, int64_t, std::owner_less<>> expiring_forwarders;

	std::shared_mutex mutex_target_address;
	std::unique_ptr<asio::ip::address> target_address;

	asio::steady_timer timer_find_timeout;
	asio::steady_timer timer_expiring_sessions;
	asio::steady_timer timer_keep_alive;
	ttp::task_group_pool &sequence_task_pool_local;
	ttp::task_group_pool &sequence_task_pool_peer;
	const size_t task_limit;

	void udp_listener_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type port_number);
	void udp_connector_incoming_to_udp(std::weak_ptr<udp_mappings> udp_session_weak_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type local_port_number);
	void udp_connector_incoming_to_udp_unpack(std::shared_ptr<udp_mappings> udp_session_weak_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type local_port_number);
	bool get_udp_target(std::shared_ptr<forwarder> target_connector, udp::endpoint &udp_target);
	bool update_udp_target(std::shared_ptr<forwarder> target_connector, udp::endpoint &udp_target);

	uint16_t generate_new_port_number(uint16_t start_port_num, uint16_t end_port_num);
	uint32_t generate_token_number();
	void cleanup_expiring_forwarders();
	void cleanup_expiring_data_connections();
	void loop_timeout_sessions();
	void loop_keep_alive();
	void find_expires(const asio::error_code &e);
	void expiring_wrapper_loops(const asio::error_code &e);
	void change_new_port(std::shared_ptr<udp_mappings> udp_mappings_ptr);
	void keep_alive(const asio::error_code &e);

public:
	client_mode() = delete;
	client_mode(const client_mode &) = delete;
	client_mode& operator=(const client_mode &) = delete;

	client_mode(asio::io_context &io_context_ref, asio::io_context &net_io, ttp::task_group_pool &seq_task_pool_local, ttp::task_group_pool &seq_task_pool_peer, size_t task_count_limit, const user_settings &settings) :
		io_context(io_context_ref),
		network_io(net_io),
		timer_find_timeout(io_context),
		timer_expiring_sessions(io_context),
		timer_keep_alive(io_context),
		sequence_task_pool_local(seq_task_pool_local),
		sequence_task_pool_peer(seq_task_pool_peer),
		task_limit(task_count_limit),
		current_settings(settings) {}

	client_mode(client_mode &&existing_client) noexcept :
		io_context(existing_client.io_context),
		network_io(existing_client.network_io),
		timer_find_timeout(std::move(existing_client.timer_find_timeout)),
		timer_expiring_sessions(std::move(existing_client.timer_expiring_sessions)),
		timer_keep_alive(std::move(existing_client.timer_keep_alive)),
		sequence_task_pool_local(existing_client.sequence_task_pool_local),
		sequence_task_pool_peer(existing_client.sequence_task_pool_peer),
		task_limit(existing_client.task_limit),
		current_settings(std::move(existing_client.current_settings)) {}
	
	~client_mode();

	bool start();
};

#endif // !__CLIENT_HPP__
