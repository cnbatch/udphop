#include <asio.hpp>

#ifndef UDPHOP_RELAY_HPP
#define UDPHOP_RELAY_HPP

#include "../networks/connections.hpp"
#include "../shares/share_defines.hpp"
#include "../shares/data_operations.hpp"

namespace modes
{
	using asio::ip::udp;
	using udp_socket = asio::use_awaitable_t<>::as_default_on_t<udp::socket>;

	class relay_mode
	{
	private:
		asio::io_context &network_io;
		asio::io_context &task_context;
		task_thread_pool::task_thread_pool &parallel_pool;
		user_settings current_settings;
		async_cipher_operations cipher_operations_ingress;
		async_cipher_operations cipher_operations_egress;

		std::unique_ptr<rfc8489::stun_header> stun_header;
		std::atomic<uint16_t> external_ipv4_port;
		std::atomic<uint32_t> external_ipv4_address;
		std::atomic<uint16_t> external_ipv6_port;
		std::array<uint8_t, 16> external_ipv6_address{};

		std::vector<udp_socket *> ipv4_udp_servers;
		std::vector<udp_socket *> ipv6_udp_servers;
		std::unordered_map<uint32_t, std::shared_ptr<udp_mappings>> udp_session_channels;

#ifdef __cpp_lib_atomic_shared_ptr
		std::deque<std::atomic<std::shared_ptr<asio::ip::address>>> target_address;
#else
		std::deque<std::shared_ptr<asio::ip::address>> target_address;
#endif
		status_records status_counters_server_role;
		status_records status_counters_forwarder_role;
		traffic_pv_records traffic_pv_counters_server_role;
		traffic_pv_records traffic_pv_counters_forwarder_role;

		asio::steady_timer timer_find_timeout;
		asio::steady_timer timer_keep_alive;
		asio::steady_timer timer_stun;
		asio::steady_timer timer_status_log;
		asio::steady_timer timer_peak_valley_traffic;
		asio::steady_timer timer_update_local_target;
		asio::steady_timer timer_detect_startup_errors;
		bool startup_has_error;
		bool fec_enabled_ingress;
		bool fec_enabled_egress;

		asio::awaitable<void> listener_ipv6_udp(uint16_t port);
		asio::awaitable<void> listener_ipv4_udp(uint16_t port);
		asio::awaitable<void> listener_ipv6_udp(asio::ip::address_v6 address, uint16_t port);
		asio::awaitable<void> listener_ipv4_udp(asio::ip::address_v4 address, uint16_t port);

		asio::awaitable<void> udp_listener_incoming(udp_socket listener_socket);
		asio::awaitable<void> udp_listener_incoming_unpack(udp_socket &listener_socket, udp::endpoint from_udp_endpoint, std::unique_ptr<uint8_t[]> original_cache, uint8_t *data_ptr, size_t data_size);
		void udp_listener_incoming_new_connection(uint8_t *data_ptr, size_t data_size, udp::endpoint from_udp_endpoint, udp_socket &listener_socket);
		void create_new_udp_connection(uint32_t iden, uint8_t *data_ptr, size_t data_size, std::shared_ptr<udp_mappings> udp_session_ptr, const udp::endpoint &peer, udp_socket &listener_socket);
		asio::awaitable<void> udp_listener_incoming_existing_connection(std::unique_ptr<uint8_t[]> original_cache, uint8_t *data_ptr, size_t data_size, udp::endpoint from_udp_endpoint, udp_socket &listener_socket, std::shared_ptr<udp_mappings> udp_session_ptr);
		asio::awaitable<void> udp_forwarder_incoming_to_udp(std::shared_ptr<udp_mappings> udp_session_ptr, std::shared_ptr<udp_socket> forwarder_socket);
		asio::awaitable<void> udp_forwarder_incoming_to_udp_unpack(std::unique_ptr<uint8_t[]> original_cache, uint8_t *data_ptr, size_t data_size, udp::endpoint remote_udp_endpoint, std::shared_ptr<udp_mappings> udp_session_ptr, std::shared_ptr<udp_socket> forwarder_socket);
		void send_by_forwarder(std::shared_ptr<udp_mappings> udp_session_ptr, std::unique_ptr<uint8_t[]> original_cache, uint8_t *data_ptr, size_t data_size);
		void send_by_listener(std::shared_ptr<udp_mappings> udp_session_ptr, std::unique_ptr<uint8_t[]> original_cache, uint8_t *data_ptr, size_t data_size);

		void udp_listener_response_test_connection(uint8_t *data_ptr, size_t data_size, udp::endpoint from_udp_endpoint, udp_socket &listener_socket);
		std::unique_ptr<udp::endpoint> get_udp_target(size_t index);
		std::unique_ptr<udp::endpoint> update_udp_target(size_t index);
		asio::awaitable<void> update_udp_target_task(size_t index, asio::steady_timer timer);

		void fec_maker_via_listener(std::shared_ptr<udp_mappings> udp_session_ptr, std::unique_ptr<uint8_t[]> original_cache, uint8_t *data, size_t data_size);
		void fec_maker_via_forwarder(std::shared_ptr<udp_mappings> udp_session_ptr, std::unique_ptr<uint8_t[]> original_cache, uint8_t *data, size_t data_size);
		std::pair<uint8_t *, size_t> fec_unpack_listener(std::shared_ptr<udp_mappings> &udp_session_ptr, uint8_t *original_data_ptr, size_t plain_size);
		std::pair<uint8_t *, size_t> fec_unpack_forwarder(std::shared_ptr<udp_mappings> &udp_session_ptr, uint8_t *original_data_ptr, size_t plain_size);
		void fec_find_missings_via_listener(std::shared_ptr<udp_mappings> udp_session_ptr, fec_control_data &fec_controllor, uint32_t fec_sn, uint8_t max_fec_data_count);
		void fec_find_missings_via_forwarder(std::shared_ptr<udp_mappings> udp_session_ptr, fec_control_data &fec_controllor, uint32_t fec_sn, uint8_t max_fec_data_count);

		void inspect_change_port_status(std::shared_ptr<udp_mappings> udp_mappings_ptr, std::shared_ptr<udp_socket> forwarder_socket);
		asio::awaitable<void> change_new_port(std::shared_ptr<udp_mappings> udp_mappings_ptr, std::shared_ptr<udp_socket> forwarder_socket);
		asio::awaitable<void> test_before_change(packet::data_wrapper &wrapper, std::shared_ptr<udp_socket> forwarder_socket, bool &success);
		asio::awaitable<void> watchdog_test_change();
		asio::awaitable<void> close_old_socket(std::shared_ptr<udp_socket> forwarder_socket);

		asio::awaitable<void> cleanup_timedout_sessions();
		asio::awaitable<void> session_keep_alive();
		void send_keep_alive(std::shared_ptr<udp_mappings> udp_session_ptr, udp_socket *sender_socket, std::shared_ptr<udp::endpoint> target_endpoint);

		asio::awaitable<void> send_stun_request();
		void save_external_ip_address(uint32_t ipv4_address, uint16_t ipv4_port, const std::array<uint8_t, 16> &ipv6_address, uint16_t ipv6_port);

		void log_status(const asio::error_code &e);
		void peak_valley_traffic(const asio::error_code &e);
		asio::awaitable<void> detect_startup_errors();

	public:
		relay_mode() = delete;
		relay_mode(const relay_mode &) = delete;
		relay_mode &operator=(const relay_mode &) = delete;

		relay_mode(asio::io_context &network_io, asio::io_context &task_context, task_thread_pool::task_thread_pool &parallel_pool, const user_settings &settings) :
			network_io(network_io),
			task_context(task_context),
			parallel_pool(parallel_pool),
			current_settings(settings),
			cipher_operations_ingress(parallel_pool, settings.ingress->encryption_password, settings.ingress->encryption),
			cipher_operations_egress(parallel_pool, settings.egress->encryption_password, settings.egress->encryption),
			timer_find_timeout(network_io),
			timer_keep_alive(network_io),
			timer_stun(network_io),
			timer_status_log(task_context),
			timer_peak_valley_traffic(task_context),
			timer_update_local_target(network_io),
			timer_detect_startup_errors(task_context),
			startup_has_error(false),
			fec_enabled_ingress(false),
			fec_enabled_egress(false) {}

		relay_mode(relay_mode &&other) noexcept :
			network_io(other.network_io),
			task_context(other.task_context),
			current_settings(other.current_settings),
			cipher_operations_ingress(parallel_pool, current_settings.ingress->encryption_password, current_settings.ingress->encryption),
			cipher_operations_egress(parallel_pool, current_settings.egress->encryption_password, current_settings.egress->encryption),
			parallel_pool(other.parallel_pool), timer_find_timeout(std::move(other.timer_find_timeout)), timer_keep_alive(std::move(other.timer_keep_alive)),
			timer_stun(std::move(other.timer_stun)),
			timer_status_log(std::move(other.timer_status_log)),
			timer_peak_valley_traffic(std::move(other.timer_peak_valley_traffic)),
			timer_update_local_target(std::move(other.timer_update_local_target)),
			timer_detect_startup_errors(std::move(other.timer_detect_startup_errors)), startup_has_error(other.startup_has_error),
			fec_enabled_ingress(other.fec_enabled_ingress),
			fec_enabled_egress(other.fec_enabled_egress) {};

		bool start();
	};
}

#endif	// UDPHOP_RELAY_HPP