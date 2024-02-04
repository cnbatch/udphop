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
#include <unordered_map>
#include <unordered_set>
#include <asio.hpp>

#include "../shares/share_defines.hpp"
#include "../3rd_party/thread_pool.hpp"
#include "../3rd_party/fecpp.hpp"
#include "stun.hpp"


using asio::ip::tcp;
using asio::ip::udp;

constexpr uint8_t TIME_GAP = std::numeric_limits<uint8_t>::max();	//seconds
constexpr size_t BUFFER_SIZE = 2048u;
constexpr size_t BUFFER_EXPAND_SIZE = 128u;
constexpr size_t EMPTY_PACKET_SIZE = 1430u;
constexpr size_t RAW_HEADER_SIZE = 12u;
constexpr size_t RETRY_TIMES = 30u;
constexpr size_t RETRY_WAITS = 2u;
constexpr size_t CLEANUP_WAITS = 10u;	// second
constexpr uint16_t FEC_WAITS = 3u;	// second
constexpr auto STUN_RESEND = std::chrono::seconds(30);
constexpr auto FINDER_TIMEOUT_INTERVAL = std::chrono::seconds(1);
constexpr auto CHANGEPORT_UPDATE_INTERVAL = std::chrono::seconds(1);
constexpr auto EXPRING_UPDATE_INTERVAL = std::chrono::seconds(2);
const asio::ip::udp::endpoint local_empty_target_v4(asio::ip::make_address_v4("127.0.0.1"), 70);
const asio::ip::udp::endpoint local_empty_target_v6(asio::ip::make_address_v6("::1"), 70);


struct udp_mappings;

using udp_callback_t = std::function<void(std::unique_ptr<uint8_t[]>, size_t, udp::endpoint, asio::ip::port_type)>;

int64_t right_now();

void empty_udp_callback(std::unique_ptr<uint8_t[]> tmp1, size_t tmps, udp::endpoint tmp2, asio::ip::port_type tmp3);

namespace packet
{
#pragma pack (push, 1)
	struct packet_layer
	{
		uint32_t iden;
		int64_t timestamp;
		uint8_t data[1];
	};

	struct packet_layer_fec
	{
		uint32_t iden;
		int64_t timestamp;
		uint32_t sn;
		uint8_t sub_sn;
		uint8_t data[1];
	};
#pragma pack(pop)

	// from https://stackoverflow.com/questions/3022552/is-there-any-standard-htonl-like-function-for-64-bits-integers-in-c
	uint64_t htonll(uint64_t value);
	uint64_t ntohll(uint64_t value);

	class data_wrapper
	{
	private:
		const uint32_t iden;
		std::weak_ptr<udp_mappings> udp_session_ptr;

	public:
		data_wrapper() = delete;
		data_wrapper(uint32_t id, std::weak_ptr<udp_mappings> related_session_ptr) :
			iden(id), udp_session_ptr(related_session_ptr) {}

		static uint32_t extract_iden(const std::vector<uint8_t> &input_data)
		{
			const packet_layer *ptr = (const packet_layer *)input_data.data();
			return ntohl(ptr->iden);
		}

		static uint32_t extract_iden(const uint8_t *input_data)
		{
			const packet_layer *ptr = (const packet_layer *)input_data;
			return ntohl(ptr->iden);
		}

		uint32_t get_iden() { return iden; }

		void write_iden(uint8_t *input_data)
		{
			packet_layer *ptr = (packet_layer *)input_data;
			ptr->iden = htonl(iden);
		}

		std::tuple<int64_t, const uint8_t *, size_t> receive_data(const uint8_t *input_data, size_t length)
		{
			const packet_layer *ptr = (const packet_layer *)input_data;
			int64_t timestamp = ntohll(ptr->timestamp);
			const uint8_t *data_ptr = ptr->data;
			size_t data_size = length - (data_ptr - input_data);

			return { timestamp, data_ptr, data_size };
		}

		std::pair<int64_t, std::vector<uint8_t>> receive_data(const std::vector<uint8_t> &input_data)
		{
			const packet_layer *ptr = (const packet_layer *)input_data.data();
			int64_t timestamp = ntohll(ptr->timestamp);
			const uint8_t *data_ptr = ptr->data;

			size_t data_size = input_data.size() - (data_ptr - input_data.data());

			return { timestamp, std::vector<uint8_t>(data_ptr, data_ptr + data_size) };
		}

		std::tuple<packet_layer_fec, const uint8_t *, size_t> receive_data_with_fec(const uint8_t *input_data, size_t length)
		{
			packet_layer_fec packet_header{};
			const packet_layer_fec *ptr = (const packet_layer_fec *)input_data;
			packet_header.timestamp = ntohll(ptr->timestamp);
			packet_header.iden = ntohl(ptr->iden);
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
			packet_header.timestamp = ntohll(ptr->timestamp);
			packet_header.iden = ntohl(ptr->iden);
			packet_header.sn = ntohl(ptr->sn);
			packet_header.sub_sn = ptr->sub_sn;
			
			const uint8_t *data_ptr = ptr->data;
			size_t data_size = input_data.size() - (data_ptr - input_data.data());

			return { packet_header, std::vector<uint8_t>(data_ptr, data_ptr + data_size) };
		}

		std::vector<uint8_t> pack_data(const uint8_t *input_data, size_t data_size)
		{
			auto timestamp = right_now();
			size_t new_size = sizeof(packet_layer) - 1 + data_size;

			std::vector<uint8_t> new_data(new_size);
			packet_layer *ptr = (packet_layer *)new_data.data();
			ptr->iden = htonl(iden);
			ptr->timestamp = htonll(timestamp);
			uint8_t *data_ptr = ptr->data;

			if (data_size > 0)
				std::copy_n(input_data, data_size, data_ptr);

			return new_data;
		}

		size_t pack_data(uint8_t *input_data, size_t data_size)
		{
			auto timestamp = right_now();
			size_t new_size = sizeof(packet_layer) - 1 + data_size;
			uint8_t new_data[BUFFER_SIZE + BUFFER_EXPAND_SIZE] = {};

			packet_layer *ptr = (packet_layer *)new_data;
			ptr->iden = htonl(iden);
			ptr->timestamp = htonll(timestamp);
			uint8_t *data_ptr = ptr->data;

			if (data_size > 0)
				std::copy_n(input_data, data_size, data_ptr);

			std::copy_n(new_data, new_size, input_data);

			return new_size;
		}

		std::vector<uint8_t> pack_data_with_fec(const uint8_t *input_data, size_t data_size, uint32_t sn, uint8_t sub_sn)
		{
			auto timestamp = right_now();
			size_t new_size = sizeof(packet_layer_fec) - 1 + data_size;

			std::vector<uint8_t> new_data(new_size);
			packet_layer_fec *ptr = (packet_layer_fec *)new_data.data();
			ptr->iden = htonl(iden);
			ptr->timestamp = htonll(timestamp);
			ptr->sn = htonl(sn);
			ptr->sub_sn = sub_sn;

			uint8_t *data_ptr = ptr->data;
			if (data_size > 0)
				std::copy_n(input_data, data_size, data_ptr);

			return new_data;
		}

		size_t pack_data_with_fec(uint8_t *input_data, size_t data_size, uint32_t sn, uint8_t sub_sn)
		{
			auto timestamp = right_now();
			size_t new_size = sizeof(packet_layer_fec) - 1 + data_size;
			uint8_t new_data[BUFFER_SIZE + BUFFER_EXPAND_SIZE] = {};

			packet_layer_fec *ptr = (packet_layer_fec *)new_data;
			ptr->iden = htonl(iden);
			ptr->timestamp = htonll(timestamp);
			ptr->sn = htonl(sn);
			ptr->sub_sn = sub_sn;

			uint8_t *data_ptr = ptr->data;
			if (data_size > 0)
				std::copy_n(input_data, data_size, data_ptr);

			std::copy_n(new_data, new_size, input_data);

			return new_size;
		}

		std::vector<uint8_t> pack_data(const std::vector<uint8_t> &input_data)
		{
			return pack_data(input_data.data(), input_data.size());
		}

		std::vector<uint8_t> pack_data_with_fec(const std::vector<uint8_t> &input_data, uint32_t sn, uint8_t sub_sn)
		{
			return pack_data_with_fec(input_data.data(), input_data.size(), sn, sub_sn);
		}
	};
}

class udp_server
{
public:
	udp_server() = delete;
	udp_server(asio::io_context &net_io, const udp::endpoint &ep, udp_callback_t callback_func)
		: port_number(ep.port()), sequence_task_pool(nullptr), resolver(net_io), connection_socket(net_io), callback(callback_func), task_limit(0)
	{
		initialise(ep);
		start_receive();
	}
	udp_server(asio::io_context &net_io, ttp::task_group_pool &task_pool, size_t task_count_limit, const udp::endpoint &ep, udp_callback_t callback_func)
		: port_number(ep.port()), sequence_task_pool(&task_pool), resolver(net_io), connection_socket(net_io), callback(callback_func), task_limit(task_count_limit)
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

	asio::ip::port_type get_port_number();

	const asio::ip::port_type port_number;
	ttp::task_group_pool *sequence_task_pool;
	udp::resolver resolver;
	udp::socket connection_socket;
	udp::endpoint incoming_endpoint;
	udp_callback_t callback;
	const size_t task_limit;
};

class udp_client
{
public:
	udp_client() = delete;
	udp_client(asio::io_context &io_context, udp_callback_t callback_func, bool v4_only = false)
		: sequence_task_pool(nullptr), connection_socket(io_context), resolver(io_context), callback(callback_func),
		task_limit(0), last_receive_time(right_now()), last_send_time(right_now()), paused(false), stopped(false), ipv4_only(v4_only)
	{
		initialise();
	}
	udp_client(asio::io_context &io_context, ttp::task_group_pool &task_pool, size_t task_count_limit, udp_callback_t callback_func, bool v4_only = false)
		: sequence_task_pool(&task_pool), connection_socket(io_context), resolver(io_context), callback(callback_func),
		task_limit(task_count_limit), last_receive_time(right_now()), last_send_time(right_now()), paused(false), stopped(false), ipv4_only(v4_only)
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

	ttp::task_group_pool *sequence_task_pool;
	udp::socket connection_socket;
	udp::resolver resolver;
	udp::endpoint incoming_endpoint;
	udp_callback_t callback;
	alignas(64) std::atomic<int64_t> last_receive_time;
	alignas(64) std::atomic<int64_t> last_send_time;
	alignas(64) std::atomic<bool> paused;
	alignas(64) std::atomic<bool> stopped;
	const size_t task_limit;
	const bool ipv4_only;
};


class forwarder : public udp_client
{
public:
	using process_data_t = std::function<void(std::weak_ptr<udp_mappings>, std::unique_ptr<uint8_t[]>, size_t, udp::endpoint, asio::ip::port_type)>;
	forwarder() = delete;
	forwarder(asio::io_context &io_context, ttp::task_group_pool &task_pool, size_t task_count_limit, std::weak_ptr<udp_mappings> input_session, process_data_t callback_func, bool v4_only = false) :
		udp_client(io_context, task_pool, task_count_limit, std::bind(&forwarder::handle_receive, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4), v4_only),
		udp_session_mappings(input_session), callback(callback_func) {}

private:
	void handle_receive(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer, asio::ip::port_type local_port_number)
	{
		if (paused.load() || stopped.load())
			return;

		if (udp_session_mappings.expired())
		{
			stop();
			return;
		}

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

struct udp_mappings
{
	std::shared_ptr<packet::data_wrapper> wrapper_ptr;
	std::shared_mutex mutex_ingress_endpoint;
	udp::endpoint ingress_source_endpoint;
	std::shared_mutex mutex_egress_endpoint;
	udp::endpoint egress_target_endpoint;
	udp::endpoint egress_previous_target_endpoint;
	std::shared_ptr<forwarder> egress_forwarder;	// client only
	alignas(64) std::atomic<udp_server*> ingress_sender;	// server only
	std::unique_ptr<udp_client> local_udp;	// server only
	alignas(64) std::atomic<int64_t> changeport_timestamp;
	fec_control_data fec_ingress_control;
	fec_control_data fec_egress_control;
};

std::unique_ptr<rfc3489::stun_header> send_stun_3489_request(udp_server &sender, const std::string &stun_host, bool v4_only = false);
std::unique_ptr<rfc8489::stun_header> send_stun_8489_request(udp_server &sender, const std::string &stun_host, bool v4_only = false);
void resend_stun_8489_request(udp_server &sender, const std::string &stun_host, rfc8489::stun_header *header, bool v4_only = false);
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
