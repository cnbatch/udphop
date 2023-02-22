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
#include <asio.hpp>

#include "../shares/share_defines.hpp"
#include "stun.hpp"


using asio::ip::tcp;
using asio::ip::udp;

constexpr uint8_t TIME_GAP = std::numeric_limits<uint8_t>::max();	//seconds
constexpr size_t BUFFER_SIZE = 4096u;
constexpr size_t BUFFER_EXPAND_SIZE = 128u;
constexpr size_t EMPTY_PACKET_SIZE = 1430u;
constexpr size_t RAW_HEADER_SIZE = 12u;
constexpr size_t RETRY_TIMES = 30u;
constexpr size_t RETRY_WAITS = 3u;
constexpr size_t TIMEOUT = 1200;	// second
constexpr size_t CLEANUP_WAITS = 10;	// second
constexpr auto STUN_RESEND = std::chrono::seconds(30);
constexpr auto FINDER_TIMEOUT_INTERVAL = std::chrono::seconds(1);
constexpr auto CHANGEPORT_UPDATE_INTERVAL = std::chrono::seconds(1);
constexpr auto EXPRING_UPDATE_INTERVAL = std::chrono::seconds(2);
const asio::ip::udp::endpoint local_empty_target(asio::ip::make_address_v6("::1"), 70);


class forwarder;

using udp_callback_t = std::function<void(std::shared_ptr<uint8_t[]>, size_t, udp::endpoint&&, asio::ip::port_type)>;

int64_t right_now();

void empty_udp_callback(std::shared_ptr<uint8_t[]> tmp1, size_t tmps, udp::endpoint &&tmp2, asio::ip::port_type tmp3);


class udp_server
{
public:
	udp_server() = delete;
	udp_server(asio::io_context &net_io, asio::strand<asio::io_context::executor_type> &asio_strand, const udp::endpoint &ep, udp_callback_t callback_func)
		: port_number(ep.port()), task_assigner(asio_strand), resolver(net_io), connection_socket(net_io), callback(callback_func)
	{
		initialise(ep);
		start_receive();
	}
	void continue_receive();
	void async_send_out(std::shared_ptr<std::vector<uint8_t>> data, const udp::endpoint &client_endpoint);
	void async_send_out(std::shared_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint &peer_endpoint);
	void async_send_out(std::shared_ptr<uint8_t[]> data, const uint8_t *data_ptr, size_t data_size, const udp::endpoint &client_endpoint);
	void async_send_out(std::vector<uint8_t> &&data, const udp::endpoint &client_endpoint);
	udp::resolver& get_resolver() { return resolver; }

private:
	void initialise(const udp::endpoint &ep);
	void start_receive();
	void handle_receive(std::shared_ptr<uint8_t[]> buffer_cache, const asio::error_code &error, std::size_t bytes_transferred);

	asio::ip::port_type get_port_number();

	asio::ip::port_type port_number;
	asio::strand<asio::io_context::executor_type> &task_assigner;
	udp::resolver resolver;
	udp::socket connection_socket;
	udp::endpoint incoming_endpoint;
	udp_callback_t callback;
};

class udp_client
{
public:
	udp_client() = delete;
	udp_client(asio::io_context &io_context, asio::strand<asio::io_context::executor_type> &asio_strand, udp_callback_t callback_func)
		: task_assigner(asio_strand), connection_socket(io_context), resolver(io_context), callback(callback_func),
		last_receive_time(right_now()), last_send_time(right_now()),
		paused(false), stopped(false)
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

	size_t send_out(const std::vector<uint8_t> &data, const udp::endpoint &peer_endpoint, asio::error_code &ec);
	size_t send_out(const uint8_t *data, size_t size, const udp::endpoint &peer_endpoint, asio::error_code &ec);

	void async_send_out(std::shared_ptr<std::vector<uint8_t>> data, const udp::endpoint &peer_endpoint);
	void async_send_out(std::shared_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint &peer_endpoint);
	void async_send_out(std::shared_ptr<uint8_t[]> data, const uint8_t *data_ptr, size_t data_size, const udp::endpoint &client_endpoint);
	void async_send_out(std::vector<uint8_t> &&data, const udp::endpoint &peer_endpoint);

	int64_t time_gap_of_receive();
	int64_t time_gap_of_send();

protected:
	void initialise();

	void start_receive();

	void handle_receive(std::shared_ptr<uint8_t[]> buffer_cache, const asio::error_code &error, std::size_t bytes_transferred);

	asio::strand<asio::io_context::executor_type> &task_assigner;
	udp::socket connection_socket;
	udp::resolver resolver;
	udp::endpoint incoming_endpoint;
	udp_callback_t callback;
	std::atomic<int64_t> last_receive_time;
	std::atomic<int64_t> last_send_time;
	std::atomic<bool> paused;
	std::atomic<bool> stopped;
};

template<typename T>
class data_wrapper
{
private:
	uint32_t iden;

public:
	std::atomic<T *> forwarder_ptr;

	data_wrapper() = delete;
	data_wrapper(uint32_t id) : iden(id) {}

	static uint32_t extract_iden(const std::vector<uint8_t> &input_data)
	{
		const uint8_t *ptr = input_data.data();
		uint32_t ident = reinterpret_cast<const decltype(ident)*>(ptr)[0];
		return ident;
	}

	static uint32_t extract_iden(const uint8_t *input_data)
	{
		uint32_t ident = reinterpret_cast<const decltype(ident)*>(input_data)[0];
		return ident;
	}

	void write_iden(uint8_t *input_data)
	{
		reinterpret_cast<decltype(iden)*>(input_data)[0] = iden;
	}

	uint32_t get_iden() { return iden; }

	std::tuple<int64_t, const uint8_t *, size_t> receive_data(const uint8_t *input_data, size_t data_size)
	{
		const uint8_t *ptr = input_data;
		uint32_t iden = reinterpret_cast<const decltype(iden)*>(ptr)[0];

		ptr = ptr + sizeof(iden);
		int64_t timestamp = reinterpret_cast<const decltype(timestamp)*>(ptr)[0];

		ptr = ptr + sizeof(timestamp);
		size_t new_data_size = data_size - (ptr - input_data);

		return { timestamp, ptr, new_data_size };
	}

	std::pair<int64_t, std::vector<uint8_t>> receive_data(const std::vector<uint8_t> &input_data)
	{
		const uint8_t *ptr = input_data.data();
		uint32_t iden = reinterpret_cast<const decltype(iden)*>(ptr)[0];

		ptr = ptr + sizeof(iden);
		int64_t timestamp = reinterpret_cast<const decltype(timestamp)*>(ptr)[0];

		ptr = ptr + sizeof(timestamp);
		size_t data_size = input_data.size() - (ptr - input_data.data());

		return { timestamp, std::vector<uint8_t>(ptr, ptr + data_size) };
	}

	std::vector<uint8_t> pack_data(const uint8_t *input_data, size_t data_size)
	{
		auto timestamp = right_now();

		std::vector<uint8_t> new_data(sizeof(iden) + sizeof(timestamp) + data_size);
		uint8_t *ptr = new_data.data();
		reinterpret_cast<decltype(iden)*>(ptr)[0] = iden;

		ptr = ptr + sizeof(iden);
		reinterpret_cast<decltype(timestamp)*>(ptr)[0] = timestamp;

		ptr = ptr + sizeof(timestamp);
		if (data_size > 0)
			std::copy_n(input_data, data_size, ptr);

		return new_data;
	}

	size_t pack_data(uint8_t *input_data, size_t data_size)
	{
		auto timestamp = right_now();
		size_t new_size = sizeof(iden) + sizeof(timestamp) + data_size;
		uint8_t new_data[BUFFER_SIZE + BUFFER_EXPAND_SIZE] = {};

		uint8_t *ptr = new_data;
		reinterpret_cast<decltype(iden)*>(ptr)[0] = iden;

		ptr = ptr + sizeof(iden);
		reinterpret_cast<decltype(timestamp)*>(ptr)[0] = timestamp;

		ptr = ptr + sizeof(timestamp);
		if (data_size > 0)
			std::copy_n(input_data, data_size, ptr);

		std::copy_n(new_data, new_size, input_data);

		return new_size;
	}

	std::vector<uint8_t> pack_data(const std::vector<uint8_t> &input_data)
	{
		return pack_data(input_data.data(), input_data.size());
	}

	void send_data(std::vector<uint8_t> &&output_data, const udp::endpoint &peer_endpoint)
	{
		if (forwarder_ptr.load() == nullptr)
			return;

		forwarder_ptr.load()->async_send_out(std::move(output_data), peer_endpoint);
	}

	void send_data(std::shared_ptr<uint8_t[]> output_data, uint8_t *start_pos, size_t data_size, const udp::endpoint &peer_endpoint)
	{
		if (forwarder_ptr.load() == nullptr)
			return;

		forwarder_ptr.load()->async_send_out(output_data, start_pos, data_size, peer_endpoint);
	}
};


class forwarder : public udp_client
{
public:
	using process_data_t = std::function<void(std::shared_ptr<data_wrapper<forwarder>>, std::shared_ptr<uint8_t[]>, size_t, udp::endpoint&&, asio::ip::port_type)>;
	forwarder() = delete;
	forwarder(asio::io_context &io_context, asio::strand<asio::io_context::executor_type> &asio_strand, std::shared_ptr<data_wrapper<forwarder>> input_wrapper, process_data_t callback_func) :
		udp_client(io_context, asio_strand, std::bind(&forwarder::handle_receive, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4)),
		wrapper(input_wrapper), callback(callback_func), task_assigner(asio_strand) {}

	void replace_callback(process_data_t callback_func)
	{
		callback = callback_func;
	}

	void remove_callback()
	{
		callback = [](std::shared_ptr<data_wrapper<forwarder>> wrapper, std::shared_ptr<uint8_t[]> data, size_t data_size, udp::endpoint &&ep, asio::ip::port_type num) {};
	}

private:
	void handle_receive(std::shared_ptr<uint8_t[]> data, size_t data_size, udp::endpoint &&peer, asio::ip::port_type local_port_number)
	{
		if (paused.load() || stopped.load())
			return;

		asio::post(task_assigner, [this, data, data_size, peer_ep = std::move(peer), local_port_number]() mutable
			{ callback(wrapper, data, data_size, std::move(peer_ep), local_port_number); });
	}

	std::shared_ptr<data_wrapper<forwarder>> wrapper;
	process_data_t callback;
	asio::strand<asio::io_context::executor_type> &task_assigner;
};

std::unique_ptr<rfc3489::stun_header> send_stun_3489_request(udp_server &sender, const std::string &stun_host);
std::unique_ptr<rfc8489::stun_header> send_stun_8489_request(udp_server &sender, const std::string &stun_host);
void resend_stun_8489_request(udp_server &sender, const std::string &stun_host, rfc8489::stun_header *header);

#endif // !__CONNECTIONS__
