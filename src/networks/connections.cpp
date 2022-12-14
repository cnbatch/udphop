#include <algorithm>
#include <chrono>
#include <memory>
#include <limits>
#include <random>
#include <thread>
#include "connections.hpp"

using namespace std::chrono;
using namespace std::literals;

int64_t right_now()
{
	auto right_now = std::chrono::system_clock::now();
	return std::chrono::duration_cast<std::chrono::seconds>(right_now.time_since_epoch()).count();
}

void empty_udp_callback(std::shared_ptr<uint8_t[]> tmp1, size_t tmps, udp::endpoint &&tmp2, asio::ip::port_type tmp3)
{
}

std::unique_ptr<rfc3489::stun_header> send_stun_3489_request(udp_server &sender, const std::string &stun_host)
{
	asio::error_code ec;
	udp::resolver &udp_resolver = sender.get_resolver();
	udp::resolver::results_type remote_addresses = udp_resolver.resolve(udp::v6(), stun_host, "3478",
		udp::resolver::numeric_service | udp::resolver::v4_mapped | udp::resolver::all_matching, ec);

	if (ec)
		return nullptr;

	auto number = generate_random_number<uint64_t>();
	std::unique_ptr<rfc3489::stun_header> header = rfc3489::create_stun_header(number);
	size_t header_size = sizeof(rfc3489::stun_header);
	for (auto &target_address : remote_addresses)
	{
		std::vector<uint8_t> data(header_size);
		std::copy_n((uint8_t *)(header.get()), header_size, data.begin());
		sender.async_send_out(std::move(data), target_address);
	}

	return header;
}

std::unique_ptr<rfc8489::stun_header> send_stun_8489_request(udp_server &sender, const std::string &stun_host)
{
	asio::error_code ec;
	udp::resolver &udp_resolver = sender.get_resolver();
	udp::resolver::results_type remote_addresses = udp_resolver.resolve(udp::v6(), stun_host, "3478",
		udp::resolver::numeric_service | udp::resolver::v4_mapped | udp::resolver::all_matching, ec);

	if (ec)
		return nullptr;

	auto number = generate_random_number<uint64_t>();
	std::unique_ptr<rfc8489::stun_header> header = rfc8489::create_stun_header(number);
	size_t header_size = sizeof(rfc8489::stun_header);

	for (auto &target_address : remote_addresses)
	{
		std::vector<uint8_t> data(header_size);
		std::copy_n((uint8_t *)header.get(), header_size, data.data());
		sender.async_send_out(std::move(data), target_address);
	}

	return header;
}

void resend_stun_8489_request(udp_server &sender, const std::string &stun_host, rfc8489::stun_header *header)
{
	asio::error_code ec;
	udp::resolver &udp_resolver = sender.get_resolver();
	udp::resolver::results_type remote_addresses = udp_resolver.resolve(udp::v6(), stun_host, "3478",
		udp::resolver::numeric_service | udp::resolver::v4_mapped | udp::resolver::all_matching, ec);

	if (ec)
		return;

	size_t header_size = sizeof(rfc8489::stun_header);
	for (auto &target_address : remote_addresses)
	{
		std::vector<uint8_t> data(header_size);
		std::copy_n((uint8_t *)header, header_size, data.data());
		sender.async_send_out(std::move(data), target_address);
	}

	return;
}





void udp_server::continue_receive()
{
	start_receive();
}

void udp_server::async_send_out(std::shared_ptr<std::vector<uint8_t>> data, const udp::endpoint &client_endpoint)
{
	connection_socket.async_send_to(asio::buffer(*data), client_endpoint,
		[data](const asio::error_code &error, size_t bytes_transferred) {});
}

void udp_server::async_send_out(std::shared_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint &peer_endpoint)
{
	connection_socket.async_send_to(asio::buffer(data.get(), data_size), peer_endpoint,
		[data](const asio::error_code &error, size_t bytes_transferred) {});
}

void udp_server::async_send_out(std::shared_ptr<uint8_t[]> data, const uint8_t *data_ptr, size_t data_size, const udp::endpoint &client_endpoint)
{
	connection_socket.async_send_to(asio::buffer(data_ptr, data_size), client_endpoint,
		[data](const asio::error_code &error, size_t bytes_transferred) {});
}

void udp_server::async_send_out(std::vector<uint8_t> &&data, const udp::endpoint &client_endpoint)
{
	auto asio_buffer = asio::buffer(data);
	connection_socket.async_send_to(asio_buffer, client_endpoint,
		[data_ = std::move(data)](const asio::error_code &error, size_t bytes_transferred) {});
}


void udp_server::initialise(const udp::endpoint &ep)
{
	asio::ip::v6_only v6_option(false);
	connection_socket.open(ep.protocol());
	connection_socket.set_option(v6_option);
	connection_socket.bind(ep);
}

void udp_server::start_receive()
{
	std::shared_ptr<uint8_t[]> buffer_cache(new uint8_t[BUFFER_SIZE]());

	connection_socket.async_receive_from(asio::buffer(buffer_cache.get(), BUFFER_SIZE), incoming_endpoint,
		[buffer_cache, this](const asio::error_code &error, std::size_t bytes_transferred)
		{
			handle_receive(buffer_cache, error, bytes_transferred);
		});
}

void udp_server::handle_receive(std::shared_ptr<uint8_t[]> buffer_cache, const asio::error_code &error, std::size_t bytes_transferred)
{
	if (error)
	{
		if (!connection_socket.is_open())
			return;
	}

	udp::endpoint copy_of_incoming_endpoint = incoming_endpoint;
	start_receive();
	if (BUFFER_SIZE - bytes_transferred < BUFFER_EXPAND_SIZE)
	{
		std::shared_ptr<uint8_t[]> new_buffer(new uint8_t[BUFFER_SIZE + BUFFER_EXPAND_SIZE]());
		std::copy_n(buffer_cache.get(), bytes_transferred, new_buffer.get());
		buffer_cache.swap(new_buffer);
	}

	asio::post(task_assigner, [this, buffer_cache, bytes_transferred, peer_ep = std::move(copy_of_incoming_endpoint)]() mutable
		{ callback(buffer_cache, bytes_transferred, std::move(peer_ep), port_number); });
}

asio::ip::port_type udp_server::get_port_number()
{
	return port_number;
}





void udp_client::pause(bool set_as_pause)
{
	bool expect = set_as_pause;
	if (paused.compare_exchange_strong(expect, set_as_pause))
		return;
	paused.store(set_as_pause);
	start_receive();
}

void udp_client::stop()
{
	std::cout << "udp session is stopped\n";
	stopped.store(true);
	callback = empty_udp_callback;
	this->disconnect();
}

bool udp_client::is_pause()
{
	return paused.load();
}

bool udp_client::is_stop()
{
	return stopped.load();
}

udp::resolver::results_type udp_client::get_remote_hostname(const std::string &remote_address, asio::ip::port_type port_num, asio::error_code &ec)
{
	return get_remote_hostname(remote_address, std::to_string(port_num), ec);
}

udp::resolver::results_type udp_client::get_remote_hostname(const std::string &remote_address, const std::string &port_num, asio::error_code &ec)
{
	udp::resolver::results_type remote_addresses = resolver.resolve(udp::v6(), remote_address, port_num,
		udp::resolver::numeric_service | udp::resolver::v4_mapped | udp::resolver::all_matching, ec);

	return remote_addresses;
}

void udp_client::disconnect()
{
	asio::error_code ec;
	connection_socket.close(ec);
}

void udp_client::async_receive()
{
	if (paused.load() || stopped.load())
		return;
	start_receive();
}

size_t udp_client::send_out(const std::vector<uint8_t> &data, const udp::endpoint &peer_endpoint, asio::error_code &ec)
{
	if (stopped.load())
		return 0;

	size_t sent_size = connection_socket.send_to(asio::buffer(data), peer_endpoint, 0, ec);
	last_send_time.store(right_now());
	return sent_size;
}

size_t udp_client::send_out(const uint8_t *data, size_t size, const udp::endpoint &peer_endpoint, asio::error_code &ec)
{
	if (stopped.load())
		return 0;

	size_t sent_size = connection_socket.send_to(asio::buffer(data, size), peer_endpoint, 0, ec);
	last_send_time.store(right_now());
	return sent_size;
}

void udp_client::async_send_out(std::shared_ptr<std::vector<uint8_t>> data, const udp::endpoint &peer_endpoint)
{
	if (stopped.load())
		return;

	connection_socket.async_send_to(asio::buffer(*data), peer_endpoint,
		[data](const asio::error_code &error, size_t bytes_transferred) {});
	last_send_time.store(right_now());
}

void udp_client::async_send_out(std::shared_ptr<uint8_t[]> data, size_t data_size, const udp::endpoint & peer_endpoint)
{
	if (stopped.load())
		return;

	connection_socket.async_send_to(asio::buffer(data.get(), data_size), peer_endpoint,
		[data](const asio::error_code &error, size_t bytes_transferred) {});
	last_send_time.store(right_now());
}

void udp_client::async_send_out(std::shared_ptr<uint8_t[]> data, const uint8_t *data_ptr, size_t data_size, const udp::endpoint &client_endpoint)
{
	connection_socket.async_send_to(asio::buffer(data_ptr, data_size), client_endpoint,
		[data](const asio::error_code &error, size_t bytes_transferred) {});
}

void udp_client::async_send_out(std::vector<uint8_t> &&data, const udp::endpoint &peer_endpoint)
{
	if (stopped.load())
		return;

	auto asio_buffer = asio::buffer(data);
	connection_socket.async_send_to(asio_buffer, peer_endpoint,
		[data_ = std::move(data)](const asio::error_code &error, size_t bytes_transferred) {});
	last_send_time.store(right_now());
}

int64_t udp_client::time_gap_of_receive()
{
	return calculate_difference(right_now(), last_receive_time.load());
}

int64_t udp_client::time_gap_of_send()
{
	return calculate_difference(right_now(), last_send_time.load());
}

void udp_client::initialise()
{
	asio::ip::v6_only v6_option(false);
	connection_socket.open(udp::v6());
	connection_socket.set_option(v6_option);
}

void udp_client::start_receive()
{
	if (paused.load() || stopped.load())
		return;

	std::shared_ptr<uint8_t[]> buffer_cache(new uint8_t[BUFFER_SIZE]());

	connection_socket.async_receive_from(asio::buffer(buffer_cache.get(), BUFFER_SIZE), incoming_endpoint,
		[buffer_cache, this](const asio::error_code &error, std::size_t bytes_transferred)
		{
			handle_receive(buffer_cache, error, bytes_transferred);
		});
}

void udp_client::handle_receive(std::shared_ptr<uint8_t[]> buffer_cache, const asio::error_code &error, std::size_t bytes_transferred)
{
	if (stopped.load())
		return;

	if (error)
	{
		if (connection_socket.is_open())
			start_receive();
		return;
	}

	last_receive_time.store(right_now());

	udp::endpoint copy_of_incoming_endpoint = incoming_endpoint;
	start_receive();
	if (BUFFER_SIZE - bytes_transferred < BUFFER_EXPAND_SIZE)
	{
		std::shared_ptr<uint8_t[]> new_buffer(new uint8_t[BUFFER_SIZE + BUFFER_EXPAND_SIZE]());
		std::copy_n(buffer_cache.get(), bytes_transferred, new_buffer.get());
		buffer_cache.swap(new_buffer);
	}

	asio::post(task_assigner, [this, buffer_cache, bytes_transferred, peer_ep = std::move(copy_of_incoming_endpoint)]() mutable
		{
			callback(buffer_cache, bytes_transferred, std::move(peer_ep), 0);
		});
}
