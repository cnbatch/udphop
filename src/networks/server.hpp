#pragma once
#include "connections.hpp"
#include <set>

#ifndef __SERVER_HPP__
#define __SERVER_HPP__


class server_mode
{
	asio::io_context &io_context;
	user_settings current_settings;
	std::unique_ptr<rfc8489::stun_header> stun_header;
	std::atomic<uint16_t> external_ipv4_port;
	std::atomic<uint32_t> external_ipv4_address;
	std::atomic<uint16_t> external_ipv6_port;
	std::shared_mutex mutex_ipv6;
	std::array<uint8_t, 16> external_ipv6_address;
	const std::array<uint8_t, 16> zero_value_array;

	std::vector<std::unique_ptr<udp_server>> udp_servers;
	std::unordered_map<udp_server*, std::shared_ptr<udp_mappings>> udp_zero_sessions;

	std::shared_mutex mutex_wrapper_channels;
	std::unordered_map<uint32_t, std::shared_ptr<udp_mappings>> udp_session_channels;

	std::mutex mutex_expiring_wrapper;
	std::unordered_map<std::shared_ptr<udp_mappings>, int64_t> expiring_udp_sessions;

	asio::steady_timer timer_expiring_sessions;
	asio::steady_timer timer_find_timeout;
	asio::steady_timer timer_stun;
	asio::steady_timer timer_keep_alive;
	asio::steady_timer timer_status_log;
	//ttp::task_group_pool &sequence_task_pool;
	//ttp::task_thread_pool *parallel_encryption_pool;
	//ttp::task_thread_pool *parallel_decryption_pool;

	std::unique_ptr<udp::endpoint> udp_target;
	std::atomic<size_t> fec_recovery_count;

	std::mutex mutex_decryptions_from_listener;
	std::deque<std::future<decryption_result_listener>> decryptions_from_listener;
	std::atomic<int> listener_decryption_task_count;

	void make_nzero_sessions();
	void udp_listener_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint &peer, udp_server *listener_ptr);
	void udp_listener_incoming_unpack(std::unique_ptr<uint8_t[]> data, size_t plain_size, const udp::endpoint &peer, udp_server *listener_ptr);
	//void sequential_extract(udp_server *listener_ptr);
	void udp_connector_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint &peer, asio::ip::port_type port_number, std::weak_ptr<udp_mappings> udp_session_ptr);

	void udp_listener_incoming_new_connection(std::unique_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint &peer, udp_server *listener_ptr);
	void udp_listener_response_test_connection(std::unique_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint &peer, udp_server *listener_ptr);

	bool create_new_udp_connection(std::unique_ptr<uint8_t[]> data, const uint8_t *data_ptr, size_t data_size, std::shared_ptr<udp_mappings> udp_session_ptr, const udp::endpoint &peer);

	bool update_local_udp_target(udp_client *target_connector);
	void save_external_ip_address(uint32_t ipv4_address, uint16_t ipv4_port, const std::array<uint8_t, 16> &ipv6_address, uint16_t ipv6_port);
	void data_sender(std::shared_ptr<udp_mappings> udp_session_ptr, const udp::endpoint &peer, std::unique_ptr<uint8_t[]> data, size_t data_size);
	//void data_sender(std::shared_ptr<udp_mappings> udp_session_ptr);
	//void parallel_encrypt(std::shared_ptr<udp_mappings> udp_session_ptr, std::shared_ptr<udp::endpoint> peer, std::unique_ptr<uint8_t[]> data, size_t data_size);
	//void parallel_decrypt(std::unique_ptr<uint8_t[]> data, size_t plain_size, const udp::endpoint &peer, udp_server *listener_ptr);
	void fec_maker(std::shared_ptr<udp_mappings> udp_session_ptr, feature feature_value, std::unique_ptr<uint8_t[]> data, size_t data_size);
	void fec_find_missings(udp_mappings *udp_session_ptr, fec_control_data &fec_controllor, uint32_t fec_sn, uint8_t max_fec_data_count);

	void cleanup_expiring_data_connections();
	void loop_timeout_sessions();
	void loop_keep_alive();
	void send_stun_request(const asio::error_code &e);
	void find_expires(const asio::error_code &e);
	void expiring_wrapper_loops(const asio::error_code &e);
	void keep_alive(const asio::error_code& e);
	void log_status(const asio::error_code &e);
	void loop_get_status();

public:
	server_mode() = delete;
	server_mode(const server_mode &) = delete;
	server_mode& operator=(const server_mode &) = delete;

	server_mode(asio::io_context &io_context_ref, /*ttp::task_group_pool &seq_task_pool, task_pool_colloector &task_pools,*/ const user_settings &settings)
		: io_context(io_context_ref),
		timer_expiring_sessions(io_context),
		timer_find_timeout(io_context),
		timer_stun(io_context),
		timer_keep_alive(io_context),
		timer_status_log(io_context),
		//sequence_task_pool(seq_task_pool),
		//parallel_encryption_pool(task_pools.parallel_encryption_pool),
		//parallel_decryption_pool(task_pools.parallel_decryption_pool),
		external_ipv4_port(0),
		external_ipv4_address(0),
		external_ipv6_port(0),
		external_ipv6_address{},
		zero_value_array{},
		current_settings(settings) {}

	server_mode(server_mode &&existing_server) noexcept
		: io_context(existing_server.io_context),
		//network_io(existing_server.network_io),
		timer_expiring_sessions(std::move(existing_server.timer_expiring_sessions)),
		timer_find_timeout(std::move(existing_server.timer_find_timeout)),
		timer_stun(std::move(existing_server.timer_stun)),
		timer_keep_alive(std::move(existing_server.timer_keep_alive)),
		timer_status_log(std::move(existing_server.timer_status_log)),
		//sequence_task_pool(existing_server.sequence_task_pool),
		//parallel_encryption_pool(existing_server.parallel_encryption_pool),
		//parallel_decryption_pool(existing_server.parallel_decryption_pool),
		external_ipv4_port(existing_server.external_ipv4_port.load()),
		external_ipv4_address(existing_server.external_ipv4_address.load()),
		external_ipv6_port(existing_server.external_ipv6_port.load()),
		external_ipv6_address{ existing_server.external_ipv6_address },
		zero_value_array{},
		current_settings(std::move(existing_server.current_settings)) {}

	~server_mode();
public:
	bool start();
};

#endif // !__SERVER_HPP__
