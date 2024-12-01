#pragma once
#include "connections.hpp"
#include <set>

#ifndef __RELAY_HPP_
#define __RELAY_HPP_

class relay_mode
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

	std::shared_mutex mutex_udp_session_channels;
	std::unordered_map<uint32_t, std::shared_ptr<udp_mappings>> udp_session_channels;

	std::shared_mutex mutex_hopping_sessions;
	std::unordered_map<std::shared_ptr<udp_mappings>, int64_t> hopping_sessions;

	std::mutex mutex_expiring_sessions;
	std::unordered_map<std::shared_ptr<udp_mappings>, int64_t> expiring_udp_sessions;
	std::mutex mutex_expiring_forwarders;
	std::unordered_map<std::shared_ptr<forwarder>, int64_t> expiring_forwarders;

#ifdef __cpp_lib_atomic_shared_ptr
	std::deque<std::atomic<std::shared_ptr<asio::ip::address>>> target_address;
#else
	std::deque<std::shared_ptr<asio::ip::address>> target_address;
#endif

	asio::steady_timer timer_expiring_sessions;
	asio::steady_timer timer_find_timeout;
	asio::steady_timer timer_stun;
	asio::steady_timer timer_keep_alive_ingress;
	asio::steady_timer timer_keep_alive_egress;
	asio::steady_timer timer_status_log;
	ttp::task_group_pool &sequence_task_pool;
	ttp::task_thread_pool *listener_parallels;
	ttp::task_thread_pool *forwarder_parallels;

	std::unique_ptr<udp::endpoint> udp_target;
	std::atomic<size_t> fec_recovery_count_ingress;
	std::atomic<size_t> fec_recovery_count_egress;

	std::mutex mutex_decryptions_from_listener;
	std::list<std::future<udp_mappings::decryption_result_listener>> decryptions_from_listener;
	std::atomic<int> listener_decryption_task_count;

	void make_nzero_sessions();
	void udp_listener_incoming(std::unique_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint &peer, udp_server *listener_ptr);
	void udp_listener_incoming_unpack(std::unique_ptr<uint8_t[]> data, size_t plain_size, const udp::endpoint &peer, udp_server *listener_ptr);
	void sequential_extract();

	void udp_listener_incoming_new_connection(std::unique_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint &peer, udp_server *listener_ptr);
	void udp_listener_response_test_connection(std::unique_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint& peer, udp_server *listener_ptr);

	void udp_forwarder_incoming_to_udp(std::weak_ptr<udp_mappings> udp_session_weak_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint &peer, asio::ip::port_type local_port_number);
	void udp_forwarder_incoming_to_udp_unpack(std::shared_ptr<udp_mappings> udp_session_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint &peer, asio::ip::port_type local_port_number);
	void udp_forwarder_incoming_to_udp_unpack(std::shared_ptr<udp_mappings> udp_session_ptr);

	std::unique_ptr<udp::endpoint> get_udp_target(std::shared_ptr<forwarder> target_connector, size_t index);
	std::unique_ptr<udp::endpoint> update_udp_target(std::shared_ptr<forwarder> target_connector, size_t index);
	void save_external_ip_address(uint32_t ipv4_address, uint16_t ipv4_port, const std::array<uint8_t, 16> &ipv6_address, uint16_t ipv6_port);
	void data_sender_via_listener(std::shared_ptr<udp_mappings> udp_session_ptr, const udp::endpoint &peer, std::unique_ptr<uint8_t[]> data, size_t data_size);
	void data_sender_via_listener(std::shared_ptr<udp_mappings> udp_session_ptr);
	void parallel_encrypt_via_listener(std::shared_ptr<udp_mappings> udp_session_ptr, std::shared_ptr<udp::endpoint> peer, std::unique_ptr<uint8_t[]> data, size_t data_size);
	void parallel_decrypt_via_listener(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, udp_server *listener_ptr);
	void data_sender_via_forwarder(std::shared_ptr<udp_mappings> udp_session_ptr, const udp::endpoint &peer, std::unique_ptr<uint8_t[]> data, size_t data_size);
	void data_sender_via_forwarder(std::shared_ptr<udp_mappings> udp_session_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size);
	void data_sender_via_forwarder(std::shared_ptr<udp_mappings> udp_session_ptr);
	void parallel_encrypt_via_forwarder(std::shared_ptr<udp_mappings> udp_session_ptr, std::shared_ptr<udp::endpoint> peer, std::unique_ptr<uint8_t[]> data, size_t data_size);
	void parallel_decrypt_via_forwarder(std::shared_ptr<udp_mappings> udp_session_ptr, std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type local_port_number);
	void fec_maker_via_listener(std::shared_ptr<udp_mappings> udp_session_ptr, feature feature_value, std::unique_ptr<uint8_t[]> data, size_t data_size);
	void fec_maker_via_forwarder(std::shared_ptr<udp_mappings> udp_session_ptr, feature feature_value, std::unique_ptr<uint8_t[]> data, size_t data_size);
	void fec_find_missings_via_listener(std::shared_ptr<udp_mappings> udp_session_ptr, fec_control_data &fec_controllor, uint32_t fec_sn, uint8_t max_fec_data_count);
	void fec_find_missings_via_forwarder(std::shared_ptr<udp_mappings> udp_session_ptr, fec_control_data &fec_controllor, uint32_t fec_sn, uint8_t max_fec_data_count);
	size_t fec_find_missings(std::shared_ptr<udp_mappings> udp_session_ptr, fec_control_data &fec_controllor, uint32_t fec_sn, uint8_t max_fec_data_count,
		std::function<void(std::shared_ptr<udp_mappings>, std::unique_ptr<uint8_t[]>, size_t)> sender_func);

	void cleanup_expiring_data_connections();
	void loop_timeout_sessions();
	void loop_keep_alive_ingress();
	void loop_keep_alive_egress();
	void loop_hopping_test();
	void send_stun_request(const asio::error_code &e);
	void find_expires(const asio::error_code &e);
	void expiring_wrapper_loops(const asio::error_code &e);
	void change_new_port(std::shared_ptr<udp_mappings> udp_mappings_ptr);
	void test_before_change(std::shared_ptr<udp_mappings> udp_mappings_ptr);
	void switch_new_port(std::shared_ptr<udp_mappings> udp_mappings_ptr);
	void verify_testing_response(std::shared_ptr<udp_mappings> udp_session_ptr, std::unique_ptr<uint8_t[]> data, size_t plain_size);
	void keep_alive_ingress(const asio::error_code& e);
	void keep_alive_egress(const asio::error_code& e);
	void log_status(const asio::error_code &e);
	void loop_get_status();

public:
	relay_mode() = delete;
	relay_mode(const relay_mode &) = delete;
	relay_mode& operator=(const relay_mode &) = delete;

	relay_mode(asio::io_context &io_context_ref, ttp::task_group_pool &seq_task_pool, task_pool_colloector &task_pools, const user_settings &settings)
		: io_context(io_context_ref),
		timer_expiring_sessions(io_context),
		timer_find_timeout(io_context),
		timer_stun(io_context),
		timer_keep_alive_ingress(io_context),
		timer_keep_alive_egress(io_context),
		timer_status_log(io_context),
		sequence_task_pool(seq_task_pool),
		listener_parallels(task_pools.listener_parallels),
		forwarder_parallels(task_pools.forwarder_parallels),
		external_ipv4_port(0),
		external_ipv4_address(0),
		external_ipv6_port(0),
		external_ipv6_address{},
		zero_value_array{},
		current_settings(settings) {}

	relay_mode(relay_mode &&existing_server) noexcept
		: io_context(existing_server.io_context),
		timer_expiring_sessions(std::move(existing_server.timer_expiring_sessions)),
		timer_find_timeout(std::move(existing_server.timer_find_timeout)),
		timer_stun(std::move(existing_server.timer_stun)),
		timer_keep_alive_ingress(std::move(existing_server.timer_keep_alive_ingress)),
		timer_keep_alive_egress(std::move(existing_server.timer_keep_alive_egress)),
		timer_status_log(std::move(existing_server.timer_status_log)),
		sequence_task_pool(existing_server.sequence_task_pool),
		listener_parallels(existing_server.listener_parallels),
		forwarder_parallels(existing_server.forwarder_parallels),
		external_ipv4_port(existing_server.external_ipv4_port.load()),
		external_ipv4_address(existing_server.external_ipv4_address.load()),
		external_ipv6_port(existing_server.external_ipv6_port.load()),
		external_ipv6_address{ existing_server.external_ipv6_address },
		zero_value_array{},
		current_settings(std::move(existing_server.current_settings)) {}

	~relay_mode();
public:
	bool start();
};

#endif	// __RELAY_HPP_