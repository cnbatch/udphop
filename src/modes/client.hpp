#include <asio.hpp>

#ifndef UDPHOP_CLIENT_HPP
#define UDPHOP_CLIENT_HPP

#include "../networks/connections.hpp"
#include "../shares/share_defines.hpp"
#include "../shares/data_operations.hpp"

namespace modes
{
	using asio::ip::udp;
	using udp_socket = asio::use_awaitable_t<>::as_default_on_t<udp::socket>;

	class client_mode
	{
	private:
		asio::io_context &network_io;
		asio::io_context &task_context;
		task_thread_pool::task_thread_pool &parallel_pool;
		user_settings current_settings;
		async_cipher_operations cipher_operations;
		std::map<udp::endpoint, std::shared_ptr<udp_mappings>> udp_endpoint_map_to_session;
		std::unordered_map<uint32_t, std::shared_ptr<udp_mappings>> udp_session_channels;

		asio::steady_timer timer_find_timeout;
		asio::steady_timer timer_keep_alive;
		asio::steady_timer timer_status_log;
		asio::steady_timer timer_peak_valley_traffic;
		asio::steady_timer timer_detect_startup_errors;

#ifdef __cpp_lib_atomic_shared_ptr
		std::deque<std::atomic<std::shared_ptr<asio::ip::address>>> target_address;
#else
		std::deque<std::shared_ptr<asio::ip::address>> target_address;
#endif
		status_records status_counters;
		traffic_pv_records traffic_pv_counters;
		bool startup_has_error;
		bool fec_enabled;

		asio::awaitable<void> listener_ipv6_udp(uint16_t port);
		asio::awaitable<void> listener_ipv4_udp(uint16_t port);
		asio::awaitable<void> listener_ipv6_udp(asio::ip::address_v6 address, uint16_t port);
		asio::awaitable<void> listener_ipv4_udp(asio::ip::address_v4 address, uint16_t port);

		asio::awaitable<void> udp_listener_incoming(udp_socket listener_socket);
		asio::awaitable<void> udp_listener_incoming_new_connection(uint8_t *data, size_t data_size, udp::endpoint peer, udp_socket &listener_socket);
		asio::awaitable<void> udp_listener_incoming_existing_connection(std::unique_ptr<uint8_t[]> original_cache, uint8_t *data, size_t data_size, udp_socket &listener_socket, std::shared_ptr<udp_mappings> udp_session_ptr);
		std::unique_ptr<udp::endpoint> get_udp_target(size_t index);
		std::unique_ptr<udp::endpoint> update_udp_target(size_t index);
		asio::awaitable<void> update_udp_target_task(size_t index, asio::steady_timer timer);
		asio::awaitable<void> update_dnstxt_task(asio::steady_timer timer);

		asio::awaitable<void> udp_forwarder_incoming_to_udp(std::shared_ptr<udp_mappings> udp_session_ptr, std::shared_ptr<udp_socket> forwarder_socket);
		asio::awaitable<void> udp_forwarder_incoming_to_udp_unpack(std::shared_ptr<udp_mappings> udp_session_ptr, std::shared_ptr<udp_socket> forwarder_socket, std::unique_ptr<uint8_t[]> original_cache, uint8_t *data_ptr, size_t data_size, udp::endpoint remote_udp_endpoint);

		void fec_maker(std::shared_ptr<udp_mappings> udp_session_ptr, std::unique_ptr<uint8_t[]> original_cache, uint8_t *data, size_t data_size);
		std::pair<uint8_t *, size_t> fec_unpack(std::shared_ptr<udp_mappings> &udp_session_ptr, uint8_t *original_data_ptr, size_t plain_size);
		void fec_find_missings(udp_mappings *udp_session_ptr, fec_control_data &fec_controllor, uint32_t fec_sn, uint8_t max_fec_data_count);

		void inspect_change_port_status(std::shared_ptr<udp_mappings> udp_mappings_ptr, std::shared_ptr<udp_socket> forwarder_socket);
		asio::awaitable<void> change_new_port(std::shared_ptr<udp_mappings> udp_mappings_ptr, std::shared_ptr<udp_socket> forwarder_socket);
		asio::awaitable<void> test_before_change(packet::data_wrapper &wrapper, std::shared_ptr<udp_socket> forwarder_socket, bool &success);
		asio::awaitable<void> watchdog_test_change();
		asio::awaitable<void> close_old_socket(std::shared_ptr<udp_socket> forwarder_socket);

		asio::awaitable<void> cleanup_timedout_sessions();
		asio::awaitable<void> session_keep_alive();

		void log_status(const asio::error_code &e);
		void peak_valley_traffic(const asio::error_code &e);

		asio::awaitable<void> detect_startup_errors();

	public:
		client_mode() = delete;
		client_mode(const client_mode &) = delete;
		client_mode &operator=(const client_mode &) = delete;

		client_mode(asio::io_context &network_io, asio::io_context &task_context, task_thread_pool::task_thread_pool &parallel_pool, const user_settings &settings) :
			network_io(network_io),
			task_context(task_context),
			parallel_pool(parallel_pool),
			current_settings(settings),
			cipher_operations(parallel_pool, settings.encryption_password, settings.encryption),
			timer_find_timeout(network_io),
			timer_keep_alive(network_io),
			timer_status_log(task_context),
			timer_peak_valley_traffic(task_context),
			timer_detect_startup_errors(task_context),
			startup_has_error(false),
			fec_enabled(false) { }

		client_mode(client_mode &&other) noexcept:
			network_io(other.network_io),
			task_context(other.task_context),
			parallel_pool(other.parallel_pool),
			current_settings(other.current_settings),
			cipher_operations(parallel_pool, current_settings.encryption_password, current_settings.encryption),
			timer_find_timeout(std::move(other.timer_find_timeout)),
			timer_keep_alive(std::move(other.timer_keep_alive)),
			timer_status_log(std::move(other.timer_status_log)),
			timer_peak_valley_traffic(std::move(other.timer_peak_valley_traffic)),
			timer_detect_startup_errors(std::move(other.timer_detect_startup_errors)),
			startup_has_error(other.startup_has_error),
			fec_enabled(other.fec_enabled) { }

		bool start();
	};
}

#endif	// UDPHOP_CLIENT_HPP