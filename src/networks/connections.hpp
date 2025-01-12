#pragma once

#ifndef __CONNECTIONS__
#define __CONNECTIONS__

#include <functional>
#include <memory>
#include <map>
#include <array>
#include <atomic>
#include <set>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <tuple>
#include <shared_mutex>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <asio.hpp>

#include "../shares/share_defines.hpp"
#include "../3rd_party/thread_pool.hpp"
#include "../3rd_party/fecpp.hpp"
#include "stun.hpp"


using asio::ip::tcp;
using asio::ip::udp;

constexpr size_t TASK_COUNT_LIMIT = 8192u;
constexpr uint8_t TIME_GAP = std::numeric_limits<uint8_t>::max();	//seconds
constexpr size_t BUFFER_SIZE = 2048u;
constexpr size_t BUFFER_EXPAND_SIZE = 128u;
constexpr size_t EMPTY_PACKET_SIZE = 1430u;
constexpr size_t SMALL_PACKET_DATA_SIZE = 3u;
constexpr size_t RAW_HEADER_SIZE = 9u;
constexpr size_t RETRY_TIMES = 30u;
constexpr size_t RETRY_WAITS = 2u;
constexpr size_t CLEANUP_WAITS = 10u;	// second
constexpr uint16_t FEC_WAITS = 3u;	// second
constexpr auto STUN_RESEND = std::chrono::seconds(30);
constexpr auto FINDER_TIMEOUT_INTERVAL = std::chrono::seconds(1);
constexpr auto CHANGEPORT_UPDATE_INTERVAL = std::chrono::seconds(1);
constexpr auto KEEP_ALIVE_UPDATE_INTERVAL = std::chrono::seconds(1);
constexpr auto LOGGING_GAP = std::chrono::seconds(30);
constexpr auto EXPRING_UPDATE_INTERVAL = std::chrono::seconds(2);
const asio::ip::udp::endpoint local_empty_target_v4(asio::ip::make_address_v4("127.0.0.1"), 70);
const asio::ip::udp::endpoint local_empty_target_v6(asio::ip::make_address_v6("::1"), 70);


struct udp_mappings;
class udp_server;

using udp_server_callback_t = std::function<void(std::unique_ptr<uint8_t[]>, size_t, udp::endpoint, udp_server*)>;
using udp_client_callback_t = std::function<void(std::unique_ptr<uint8_t[]>, size_t, udp::endpoint, asio::ip::port_type)>;
using sequence_callback_t = std::function<void(size_t, ttp::task_callback, std::unique_ptr<uint8_t[]>)>;

int64_t right_now();

void empty_udp_server_callback(std::unique_ptr<uint8_t[]> tmp1, size_t tmps, udp::endpoint tmp2, udp_server *tmp3);
void empty_udp_client_callback(std::unique_ptr<uint8_t[]> tmp1, size_t tmps, udp::endpoint tmp2, asio::ip::port_type tmp3);

enum class feature : uint8_t
{
	keep_alive,
	test_connection,
	keep_alive_response,
	raw_data
};

enum class hop_status : uint8_t
{
	pending,
	available,
	testing
};

enum class task_type { sequence, in_place };

namespace packet
{
#pragma pack (push, 1)
	struct packet_layer
	{
		uint32_t timestamp;
		uint32_t iden;
		feature feature_value;
		uint8_t data[1];
	};

	struct packet_layer_fec
	{
		uint32_t timestamp;
		uint32_t iden;
		feature feature_value;
		uint32_t sn;
		uint8_t sub_sn;
		uint8_t data[1];
	};
#pragma pack(pop)

	uint64_t htonll(uint64_t value) noexcept;
	uint64_t ntohll(uint64_t value) noexcept;
	int64_t htonll(int64_t value) noexcept;
	int64_t ntohll(int64_t value) noexcept;
	uint16_t little_endian_to_host(uint16_t value) noexcept;
	uint16_t host_to_little_endian(uint16_t value) noexcept;
	uint32_t little_endian_to_host(uint32_t value) noexcept;
	uint32_t host_to_little_endian(uint32_t value) noexcept;
	uint64_t little_endian_to_host(uint64_t value) noexcept;
	uint64_t host_to_little_endian(uint64_t value) noexcept;
	int16_t little_endian_to_host(int16_t value) noexcept;
	int16_t host_to_little_endian(int16_t value) noexcept;
	int32_t little_endian_to_host(int32_t value) noexcept;
	int32_t host_to_little_endian(int32_t value) noexcept;
	int64_t little_endian_to_host(int64_t value) noexcept;
	int64_t host_to_little_endian(int64_t value) noexcept;

	class data_wrapper
	{
	private:
		const uint32_t iden;
		std::weak_ptr<udp_mappings> udp_session_ptr;

	public:
		data_wrapper() = delete;
		data_wrapper(uint32_t id, std::weak_ptr<udp_mappings> related_session_ptr) :
			iden(id), udp_session_ptr(related_session_ptr) {}

		static uint32_t extract_iden(const std::vector<uint8_t> &input_data) noexcept
		{
			const packet_layer *ptr = (const packet_layer *)input_data.data();
			return ntohl(ptr->iden);
		}

		static uint32_t extract_iden(const uint8_t *input_data) noexcept
		{
			const packet_layer *ptr = (const packet_layer *)input_data;
			return ntohl(ptr->iden);
		}

		uint32_t get_iden() const noexcept { return iden; }

		void write_iden(uint8_t *input_data) const noexcept
		{
			packet_layer *ptr = (packet_layer *)input_data;
			ptr->iden = htonl(iden);
		}

		std::tuple<uint32_t, feature, const uint8_t *, size_t> receive_data(const uint8_t *input_data, size_t length)
		{
			const packet_layer *ptr = (const packet_layer *)input_data;
			uint32_t timestamp = little_endian_to_host(ptr->timestamp);
			feature feature_value = ptr->feature_value;
			const uint8_t *data_ptr = ptr->data;
			size_t data_size = length - (data_ptr - input_data);

			return { timestamp, feature_value, data_ptr, data_size };
		}

		std::tuple<uint32_t, feature, std::vector<uint8_t>> receive_data(const std::vector<uint8_t> &input_data)
		{
			const packet_layer *ptr = (const packet_layer *)input_data.data();
			uint32_t timestamp = little_endian_to_host(ptr->timestamp);
			feature feature_value = ptr->feature_value;
			const uint8_t *data_ptr = ptr->data;

			size_t data_size = input_data.size() - (data_ptr - input_data.data());

			return { timestamp, feature_value, std::vector<uint8_t>(data_ptr, data_ptr + data_size) };
		}

		std::tuple<packet_layer_fec, const uint8_t *, size_t> receive_data_with_fec(const uint8_t *input_data, size_t length)
		{
			packet_layer_fec packet_header{};
			const packet_layer_fec *ptr = (const packet_layer_fec *)input_data;
			packet_header.timestamp = little_endian_to_host(ptr->timestamp);
			packet_header.iden = ntohl(ptr->iden);
			packet_header.feature_value = ptr->feature_value;
			packet_header.sn = ntohl(ptr->sn);
			packet_header.sub_sn = ptr->sub_sn;

			const uint8_t *data_ptr = ptr->data;
			size_t data_size = length - (data_ptr - input_data);

			return { packet_header, data_ptr, data_size };
		}

		std::pair<packet_layer_fec, std::vector<uint8_t>> receive_data_with_fec(const std::vector<uint8_t> &input_data)
		{
			packet_layer_fec packet_header{};
			const packet_layer_fec *ptr = (const packet_layer_fec *)input_data.data();
			packet_header.timestamp = little_endian_to_host(ptr->timestamp);
			packet_header.feature_value = ptr->feature_value;
			packet_header.iden = ntohl(ptr->iden);
			packet_header.sn = ntohl(ptr->sn);
			packet_header.sub_sn = ptr->sub_sn;
			
			const uint8_t *data_ptr = ptr->data;
			size_t data_size = input_data.size() - (data_ptr - input_data.data());

			return { packet_header, std::vector<uint8_t>(data_ptr, data_ptr + data_size) };
		}

		std::pair<std::unique_ptr<uint8_t[]>, size_t> pack_data(feature feature_value, const uint8_t *input_data, size_t data_size) const
		{
			auto timestamp = right_now();
			size_t new_size = sizeof(packet_layer) - 1 + data_size;
			std::unique_ptr<uint8_t[]> new_data = std::make_unique<uint8_t[]>(new_size + BUFFER_EXPAND_SIZE);

			packet_layer *ptr = (packet_layer *)new_data.get();
			ptr->timestamp = host_to_little_endian((uint32_t)timestamp);
			ptr->iden = htonl(iden);
			ptr->feature_value = feature_value;
			uint8_t *data_ptr = ptr->data;

			if (data_size > 0)
				std::copy_n(input_data, data_size, data_ptr);

			return { std::move(new_data), new_size };
		}

		size_t pack_data(feature feature_value, uint8_t *input_data, size_t data_size) const
		{
			auto timestamp = right_now();
			size_t new_size = sizeof(packet_layer) - 1 + data_size;
			uint8_t new_data[BUFFER_SIZE + BUFFER_EXPAND_SIZE] = {};

			packet_layer *ptr = (packet_layer *)new_data;
			ptr->timestamp = host_to_little_endian((uint32_t)timestamp);
			ptr->iden = htonl(iden);
			ptr->feature_value = feature_value;
			uint8_t *data_ptr = ptr->data;

			if (data_size > 0)
				std::copy_n(input_data, data_size, data_ptr);

			std::copy_n(new_data, new_size, input_data);

			return new_size;
		}

		std::pair<std::unique_ptr<uint8_t[]>, size_t> pack_data_with_fec(feature feature_value, const uint8_t *input_data, size_t data_size, uint32_t sn, uint8_t sub_sn) const
		{
			auto timestamp = right_now();
			size_t new_size = sizeof(packet_layer_fec) - 1 + data_size;
			std::unique_ptr<uint8_t[]> new_data = std::make_unique<uint8_t[]>(new_size + BUFFER_EXPAND_SIZE);

			packet_layer_fec *ptr = (packet_layer_fec *)new_data.get();
			ptr->timestamp = host_to_little_endian((uint32_t)timestamp);
			ptr->iden = htonl(iden);
			ptr->feature_value = feature_value;
			ptr->sn = htonl(sn);
			ptr->sub_sn = sub_sn;

			uint8_t *data_ptr = ptr->data;
			if (data_size > 0)
				std::copy_n(input_data, data_size, data_ptr);

			return { std::move(new_data) , new_size };
		}

		size_t pack_data_with_fec(feature feature_value, uint8_t *input_data, size_t data_size, uint32_t sn, uint8_t sub_sn) const
		{
			auto timestamp = right_now();
			size_t new_size = sizeof(packet_layer_fec) - 1 + data_size;
			uint8_t new_data[BUFFER_SIZE + BUFFER_EXPAND_SIZE] = {};

			packet_layer_fec *ptr = (packet_layer_fec *)new_data;
			ptr->timestamp = host_to_little_endian((uint32_t)timestamp);
			ptr->iden = htonl(iden);
			ptr->feature_value = feature_value;
			ptr->sn = htonl(sn);
			ptr->sub_sn = sub_sn;

			uint8_t *data_ptr = ptr->data;
			if (data_size > 0)
				std::copy_n(input_data, data_size, data_ptr);

			std::copy_n(new_data, new_size, input_data);

			return new_size;
		}

		std::pair<std::unique_ptr<uint8_t[]>, size_t> pack_data(feature feature_value, const std::vector<uint8_t> &input_data) const
		{
			return pack_data(feature_value, input_data.data(), input_data.size());
		}

		std::pair<std::unique_ptr<uint8_t[]>, size_t> pack_data_with_fec(feature feature_value, const std::vector<uint8_t> &input_data, uint32_t sn, uint8_t sub_sn) const
		{
			return pack_data_with_fec(feature_value, input_data.data(), input_data.size(), sn, sub_sn);
		}

		uint32_t unpack_test_iden(const uint8_t *input_data)
		{
			if (input_data == nullptr)
				return 0;
			const uint32_t *data = (const uint32_t *)input_data;
			uint32_t iden_number = ntohl(data[0]);
			return iden_number;
		}

		std::pair<std::unique_ptr<uint8_t[]>, size_t> create_random_small_packet() const
		{
			constexpr size_t data_size = sizeof(uint32_t) * SMALL_PACKET_DATA_SIZE;
			std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(BUFFER_SIZE);
			std::fill_n((uint32_t*)data.get(), SMALL_PACKET_DATA_SIZE, generate_token_number());
			return { std::move(data), data_size };
		}

		std::pair<std::unique_ptr<uint8_t[]>, size_t> create_small_packet() const
		{
			constexpr size_t data_size = sizeof(uint32_t) * SMALL_PACKET_DATA_SIZE;
			std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(BUFFER_SIZE);
			uint32_t fill_number = htonl(iden);
			std::fill_n((uint32_t*)data.get(), SMALL_PACKET_DATA_SIZE, fill_number);
			return { std::move(data), data_size };
		}

		std::pair<std::unique_ptr<uint8_t[]>, size_t> create_small_packet(uint32_t input_iden) const
		{
			constexpr size_t data_size = sizeof(uint32_t) * SMALL_PACKET_DATA_SIZE;
			std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(BUFFER_SIZE);
			uint32_t fill_number = htonl(input_iden);
			std::fill_n((uint32_t*)data.get(), SMALL_PACKET_DATA_SIZE, fill_number);
			return { std::move(data), data_size };
		}

		std::pair<std::unique_ptr<uint8_t[]>, size_t> create_keep_alive_packet() const
		{
			auto [data, data_size] = create_random_small_packet();
			size_t packed_size = pack_data(feature::keep_alive, data.get(), data_size);
			return { std::move(data), packed_size };
		}

		std::pair<std::unique_ptr<uint8_t[]>, size_t> create_keep_alive_response_packet() const
		{
			auto [data, data_size] = create_random_small_packet();
			size_t packed_size = pack_data(feature::keep_alive_response, data.get(), data_size);
			return { std::move(data), packed_size };
		}

		std::pair<std::unique_ptr<uint8_t[]>, size_t> create_test_connection_packet() const
		{
			auto [data, data_size] = create_small_packet();
			size_t packed_size = pack_data(feature::test_connection, data.get(), data_size);
			return { std::move(data), packed_size };
		}

		std::pair<std::unique_ptr<uint8_t[]>, size_t> create_test_connection_packet(uint32_t input_iden) const
		{
			auto [data, data_size] = create_small_packet(input_iden);
			size_t packed_size = pack_data(feature::test_connection, data.get(), data_size);
			return { std::move(data), packed_size };
		}
	};
}

class udp_server
{
public:
	udp_server() = delete;
	udp_server(asio::io_context &net_io, const udp::endpoint &ep, udp_server_callback_t callback_func, ip_only_options ip_ver_only = ip_only_options::not_set)
		: binded_endpoint(ep), resolver(net_io), connection_socket(net_io), callback(callback_func), ip_version_only(ip_ver_only), task_type_running(task_type::in_place)
	{
		initialise(ep);
		start_receive();
	}
	udp_server(asio::io_context &net_io, sequence_callback_t task_function, const udp::endpoint &ep, udp_server_callback_t callback_func, ip_only_options ip_ver_only = ip_only_options::not_set)
		: binded_endpoint(ep), task_type_running(task_type::sequence), push_task_seq(task_function), resolver(net_io), connection_socket(net_io), callback(callback_func), ip_version_only(ip_ver_only)
	{
		initialise(ep);
		start_receive();
	}
	void continue_receive();
	void async_send_out(std::unique_ptr<std::vector<uint8_t>> data, udp::endpoint client_endpoint);
	void async_send_out(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer_endpoint);
	void async_send_out(std::unique_ptr<uint8_t[]> data, const uint8_t *data_ptr, size_t data_size, udp::endpoint client_endpoint);
	void async_send_out(std::vector<uint8_t> &&data, udp::endpoint client_endpoint);
	void async_send_out(std::vector<uint8_t> &&data, const uint8_t *data_ptr, size_t data_size, udp::endpoint client_endpoint);
	udp::resolver& get_resolver() { return resolver; }

private:
	void initialise(udp::endpoint ep);
	void start_receive();
	void handle_receive(std::unique_ptr<uint8_t[]> buffer_cache, const asio::error_code &error, std::size_t bytes_transferred);

	udp::resolver resolver;
	udp::socket connection_socket;
	const udp::endpoint binded_endpoint;
	udp::endpoint incoming_endpoint;
	udp_server_callback_t callback;
	task_type task_type_running;
	sequence_callback_t push_task_seq;
	const ip_only_options ip_version_only;
	static inline std::atomic<size_t> task_count{};
};

class udp_client
{
public:
	udp_client() = delete;
	udp_client(asio::io_context &io_context, udp_client_callback_t callback_func, ip_only_options ip_ver_only = ip_only_options::not_set)
		: task_type_running(task_type::in_place), connection_socket(io_context), resolver(io_context), callback(callback_func),
		last_receive_time(right_now()), last_send_time(right_now()), paused(false), stopped(false), ip_version_only(ip_ver_only)
	{
		initialise();
	}
	udp_client(asio::io_context &io_context, sequence_callback_t task_function, udp_client_callback_t callback_func, ip_only_options ip_ver_only = ip_only_options::not_set)
		: task_type_running(task_type::in_place), push_task_seq(task_function), connection_socket(io_context), resolver(io_context), callback(callback_func),
		last_receive_time(right_now()), last_send_time(right_now()), paused(false), stopped(false), ip_version_only(ip_ver_only)
	{
		initialise();
	}

	void pause(bool set_as_pause);
	void stop();
	bool is_pause();
	bool is_stop();

	udp::resolver::results_type get_remote_hostname(const std::string &remote_address, asio::ip::port_type port_num, asio::error_code &ec);
	udp::resolver::results_type get_remote_hostname(const std::string &remote_address, const std::string &port_num, asio::error_code &ec);

	void disconnect();

	void async_receive();

	size_t send_out(const std::vector<uint8_t> &data, udp::endpoint peer_endpoint, asio::error_code &ec);
	size_t send_out(const uint8_t *data, size_t size, udp::endpoint peer_endpoint, asio::error_code &ec);

	void async_send_out(std::unique_ptr<std::vector<uint8_t>> data, udp::endpoint peer_endpoint);
	void async_send_out(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer_endpoint);
	void async_send_out(std::unique_ptr<uint8_t[]> data, const uint8_t *data_ptr, size_t data_size, udp::endpoint client_endpoint);
	void async_send_out(std::vector<uint8_t> &&data, udp::endpoint peer_endpoint);
	void async_send_out(std::vector<uint8_t> &&data, const uint8_t *data_ptr, size_t data_size, udp::endpoint client_endpoint);

	int64_t time_gap_of_receive();
	int64_t time_gap_of_send();

protected:
	void initialise();

	void start_receive();

	void handle_receive(std::unique_ptr<uint8_t[]> buffer_cache, const asio::error_code &error, std::size_t bytes_transferred);

	udp::socket connection_socket;
	udp::resolver resolver;
	udp::endpoint incoming_endpoint;
	udp_client_callback_t callback;
	alignas(64) std::atomic<int64_t> last_receive_time;
	alignas(64) std::atomic<int64_t> last_send_time;
	alignas(64) std::atomic<bool> paused;
	alignas(64) std::atomic<bool> stopped;
	task_type task_type_running;
	sequence_callback_t push_task_seq;
	const ip_only_options ip_version_only;
	static inline std::atomic<size_t> task_count{};
};


class forwarder : public udp_client
{
public:
	using process_data_t = std::function<void(std::weak_ptr<udp_mappings>, std::unique_ptr<uint8_t[]>, size_t, udp::endpoint, asio::ip::port_type)>;
	forwarder() = delete;
	forwarder(asio::io_context &io_context, sequence_callback_t task_function, std::weak_ptr<udp_mappings> input_session, process_data_t callback_func, ip_only_options ip_ver_only = ip_only_options::not_set) :
		udp_client(io_context, task_function, std::bind(&forwarder::handle_receive, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4), ip_ver_only),
		udp_session_mappings(input_session), callback(callback_func) {}

private:
	void handle_receive(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type local_port_number)
	{
		if (paused.load() || stopped.load())
			return;

		if (udp_session_mappings.expired())
			return;

		callback(udp_session_mappings, std::move(data), data_size, peer, local_port_number);
	}

	std::weak_ptr<udp_mappings> udp_session_mappings;
	process_data_t callback;
};

struct fec_control_data
{
	alignas(64) std::atomic<uint32_t> fec_snd_sn;
	alignas(64) std::atomic<uint32_t> fec_snd_sub_sn;
	std::vector<std::pair<std::unique_ptr<uint8_t[]>, size_t>> fec_snd_cache;
	std::map<uint32_t, std::map<uint16_t, std::pair<std::unique_ptr<uint8_t[]>, size_t>>> fec_rcv_cache;	// uint32_t = snd_sn, uint16_t = sub_sn
	std::unordered_set<uint32_t> fec_rcv_restored;
	fecpp::fec_code fecc;
};

struct encryption_result
{
	std::string error_message;
	std::unique_ptr<uint8_t[]> data;
	size_t data_size;
	std::shared_ptr<udp::endpoint> udp_endpoint;
};

struct decryption_result_listener
{
	std::string error_message;
	std::unique_ptr<uint8_t[]> data;
	size_t data_size;
	udp::endpoint udp_endpoint;
	udp_server *listener;
};

struct decryption_result_forwarder
{
	std::string error_message;
	std::unique_ptr<uint8_t[]> data;
	size_t data_size;
	udp::endpoint udp_endpoint;
	asio::ip::port_type port_number;
};

struct udp_mappings
{
	std::unique_ptr<packet::data_wrapper> wrapper_ptr;
#ifdef __cpp_lib_atomic_shared_ptr
	std::atomic<std::shared_ptr<udp::endpoint>> ingress_source_endpoint;
	std::atomic<std::shared_ptr<udp::endpoint>> egress_target_endpoint;
	std::atomic<std::shared_ptr<udp::endpoint>> egress_previous_target_endpoint;
	std::atomic<std::shared_ptr<forwarder>> egress_forwarder;	// client only
#else
	std::shared_ptr<udp::endpoint> ingress_source_endpoint;
	std::shared_ptr<udp::endpoint> egress_target_endpoint;
	std::shared_ptr<udp::endpoint> egress_previous_target_endpoint;
	std::shared_ptr<forwarder> egress_forwarder;	// client only
#endif
	std::atomic<size_t> egress_endpoint_index;
	alignas(64) std::atomic<udp_server*> ingress_sender;
	std::unique_ptr<udp_client> local_udp;	// server only
	alignas(64) std::atomic<int64_t> hopping_timestamp;
	alignas(64) std::atomic<hop_status> hopping_available;
	std::unique_ptr<packet::data_wrapper> hopping_wrapper_ptr;
	std::atomic<size_t> hopping_endpoint_index;
#ifdef __cpp_lib_atomic_shared_ptr
	std::atomic<std::shared_ptr<forwarder>> egress_hopping_forwarder;
	std::atomic<std::shared_ptr<udp::endpoint>> hopping_endpoint;
#else
	std::shared_ptr<forwarder> egress_hopping_forwarder;
	std::shared_ptr<udp::endpoint> hopping_endpoint;
#endif
	std::function<void()> mapping_function = []() {};
	fec_control_data fec_ingress_control;
	fec_control_data fec_egress_control;
	alignas(64) std::atomic<int64_t> keep_alive_ingress_timestamp{ std::numeric_limits<int64_t>::max() };
	alignas(64) std::atomic<int64_t> keep_alive_egress_timestamp{ std::numeric_limits<int64_t>::max() };
	alignas(64) std::atomic<int64_t> last_ingress_receive_time{ std::numeric_limits<int64_t>::max() };
	alignas(64) std::atomic<int64_t> last_inress_send_time{ std::numeric_limits<int64_t>::max() };
	alignas(64) std::atomic<int64_t> last_egress_receive_time{ std::numeric_limits<int64_t>::max() };
	alignas(64) std::atomic<int64_t> last_egress_send_time{ std::numeric_limits<int64_t>::max() };
	std::mutex mutex_encryptions_via_listener;
	std::deque<std::future<encryption_result>> encryptions_via_listener;
	std::mutex mutex_encryptions_via_forwarder;
	std::deque<std::future<encryption_result>> encryptions_via_forwarder;
	std::mutex mutex_decryptions_from_forwarder;
	std::deque<std::future<decryption_result_forwarder>> decryptions_from_forwarder;
	std::atomic<int> listener_encryption_task_count;
	std::atomic<int> forwarder_encryption_task_count;
	std::atomic<int> forwarder_decryption_task_count;
};

int64_t time_gap_of_ingress_receive(udp_mappings *ptr);
int64_t time_gap_of_ingress_send(udp_mappings *ptr);
int64_t time_gap_of_egress_receive(udp_mappings *ptr);
int64_t time_gap_of_egress_send(udp_mappings *ptr);


std::unique_ptr<rfc3489::stun_header> send_stun_3489_request(udp_server &sender, const std::string &stun_host, ip_only_options ip_version_only = ip_only_options::not_set);
std::unique_ptr<rfc8489::stun_header> send_stun_8489_request(udp_server &sender, const std::string &stun_host, ip_only_options ip_version_only = ip_only_options::not_set);
void resend_stun_8489_request(udp_server &sender, const std::string &stun_host, rfc8489::stun_header *header, ip_only_options ip_version_only = ip_only_options::not_set);
template<typename T>
auto split_resolved_addresses(const asio::ip::basic_resolver_results<T> &input_addresses)
{
	std::vector<asio::ip::basic_endpoint<T>> stun_servers_ipv4;
	std::vector<asio::ip::basic_endpoint<T>> stun_servers_ipv6;
	for (auto &target_address : input_addresses)
	{
		auto ep = target_address.endpoint();
		auto ep_address = ep.address();
		if (ep_address.is_v4())
		{
			stun_servers_ipv4.emplace_back(ep);
			continue;
		}

		if (ep_address.is_v6())
		{
			if (ep_address.to_v6().is_v4_mapped())
				stun_servers_ipv4.emplace_back(ep);
			else
				stun_servers_ipv6.emplace_back(target_address.endpoint());
		}
	}

	return std::pair{ stun_servers_ipv4 , stun_servers_ipv6 };
}


#endif // !__CONNECTIONS__
