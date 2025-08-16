#include <asio.hpp>

#ifndef UDPHOP_SERVER_HPP
#define UDPHOP_SERVER_HPP

#include "../networks/connections.hpp"
#include "../shares/share_defines.hpp"
#include "../shares/data_operations.hpp"

namespace modes
{
	using asio::ip::udp;
	using udp_socket = asio::use_awaitable_t<>::as_default_on_t<udp::socket>;

	class server_mode
	{
	private:
		asio::io_context &network_io;
		asio::io_context &task_context;
		task_thread_pool::task_thread_pool &parallel_pool;
		user_settings current_settings;
		async_cipher_operations cipher_operations;

		std::unique_ptr<rfc8489::stun_header> stun_header;
		std::atomic<uint16_t> external_ipv4_port;
		std::atomic<uint32_t> external_ipv4_address;
		std::atomic<uint16_t> external_ipv6_port;
		std::array<uint8_t, 16> external_ipv6_address{};

		std::vector<udp_socket *> ipv4_udp_servers;
		std::vector<udp_socket *> ipv6_udp_servers;
		std::unordered_map<uint32_t, std::shared_ptr<udp_mappings>> udp_session_channels;

		std::unique_ptr<udp::endpoint> udp_target;
		status_records status_counters;
		traffic_pv_records traffic_pv_counters;

		asio::steady_timer timer_find_timeout;
		asio::steady_timer timer_keep_alive;
		asio::steady_timer timer_stun;
		asio::steady_timer timer_status_log;
		asio::steady_timer timer_peak_valley_traffic;
		asio::steady_timer timer_update_local_target;
		asio::steady_timer timer_detect_startup_errors;
		bool startup_has_error;
		bool fec_enabled;

		asio::awaitable<void> listener_ipv6_udp(uint16_t port);
		asio::awaitable<void> listener_ipv4_udp(uint16_t port);
		asio::awaitable<void> listener_ipv6_udp(asio::ip::address_v6 address, uint16_t port);
		asio::awaitable<void> listener_ipv4_udp(asio::ip::address_v4 address, uint16_t port);

		asio::awaitable<void> udp_listener_incoming(udp_socket listener_socket);
		asio::awaitable<void> udp_listener_incoming_unpack(udp_socket &listener_socket, udp::endpoint from_udp_endpoint, std::unique_ptr<uint8_t[]> original_cache, uint8_t *data_ptr, size_t data_size);
		void udp_listener_incoming_new_connection(uint8_t *data_ptr, size_t data_size, udp::endpoint from_udp_endpoint, udp_socket &listener_socket);
		bool create_new_udp_connection(const uint8_t *data_ptr, size_t data_size, std::shared_ptr<udp_mappings> udp_session_ptr, const udp::endpoint &peer);
		asio::awaitable<void> udp_listener_incoming_existing_connection(std::unique_ptr<uint8_t[]> original_cache, uint8_t *data_ptr, size_t data_size, udp::endpoint from_udp_endpoint, udp_socket &listener_socket, std::shared_ptr<udp_mappings> udp_session_ptr);
		asio::awaitable<void> udp_connector_incoming(std::weak_ptr<udp_mappings> udp_session_weak_ptr);

		void udp_listener_response_test_connection(udp_socket &listener_socket, uint8_t *data_ptr, size_t data_size, udp::endpoint from_udp_endpoint);
		bool update_local_udp_target();
		asio::awaitable<void> update_local_udp_target_task();

		void fec_maker(std::shared_ptr<udp_mappings> udp_session_ptr, std::unique_ptr<uint8_t[]> original_cache, uint8_t *data, size_t data_size);
		std::pair<uint8_t *, size_t> fec_unpack(std::shared_ptr<udp_mappings> &udp_session_ptr, uint8_t *original_data_ptr, size_t plain_size);
		void fec_find_missings(udp_mappings *udp_session_ptr, fec_control_data &fec_controllor, uint32_t fec_sn, uint8_t max_fec_data_count);

		asio::awaitable<void> cleanup_timedout_sessions();
		asio::awaitable<void> session_keep_alive();

		asio::awaitable<void> send_stun_request();
		void save_external_ip_address(uint32_t ipv4_address, uint16_t ipv4_port, const std::array<uint8_t, 16> &ipv6_address, uint16_t ipv6_port);

		void log_status(const asio::error_code &e);
		void peak_valley_traffic(const asio::error_code &e);

		asio::awaitable<void> detect_startup_errors();

	public:
		server_mode() = delete;
		server_mode(const server_mode &) = delete;
		server_mode &operator=(const server_mode &) = delete;

		server_mode(asio::io_context &network_io, asio::io_context &task_context, task_thread_pool::task_thread_pool &parallel_pool, const user_settings &settings) :
			network_io(network_io),
			task_context(task_context),
			parallel_pool(parallel_pool),
			current_settings(settings),
			cipher_operations(parallel_pool, settings.encryption_password, settings.encryption),
			timer_find_timeout(network_io),
			timer_keep_alive(network_io),
			timer_stun(network_io),
			timer_status_log(task_context),
			timer_peak_valley_traffic(task_context),
			timer_update_local_target(network_io),
			timer_detect_startup_errors(task_context),
			startup_has_error(false),
			fec_enabled(false) {}

		server_mode(server_mode &&other) noexcept :
			network_io(other.network_io),
			task_context(other.task_context),
			current_settings(other.current_settings),
			cipher_operations(parallel_pool, current_settings.encryption_password, current_settings.encryption),
			parallel_pool(other.parallel_pool), timer_find_timeout(std::move(other.timer_find_timeout)),
			timer_keep_alive(std::move(other.timer_keep_alive)),
			timer_stun(std::move(other.timer_stun)),
			timer_status_log(std::move(other.timer_status_log)),
			timer_peak_valley_traffic(std::move(other.timer_peak_valley_traffic)),
			timer_update_local_target(std::move(other.timer_update_local_target)),
			timer_detect_startup_errors(std::move(other.timer_detect_startup_errors)),
			startup_has_error(other.startup_has_error),
			fec_enabled(other.fec_enabled){ }

		bool start();
	};

}

#endif	//UDPHOP_SERVER_HPP
