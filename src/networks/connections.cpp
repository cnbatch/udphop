#include <algorithm>
#include <bit>
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

void empty_udp_callback(std::unique_ptr<uint8_t[]> tmp1, size_t tmps, udp::endpoint tmp2, asio::ip::port_type tmp3)
{
}

namespace packet
{
	uint64_t htonll(uint64_t value) noexcept
	{
		if constexpr (std::endian::native == std::endian::little)
		{
			const uint32_t high_part = htonl(static_cast<uint32_t>(value >> 32));
			const uint32_t low_part = htonl(static_cast<uint32_t>(value & 0xFFFFFFFFLL));
			uint64_t converted_value = (static_cast<uint64_t>(low_part) << 32) | high_part;
			return converted_value;
		}
		else return value;
	}

	uint64_t ntohll(uint64_t value) noexcept
	{
		// Check the endianness
		if constexpr (std::endian::native == std::endian::little)
		{
			const uint32_t high_part = ntohl(static_cast<uint32_t>(value >> 32));
			const uint32_t low_part = ntohl(static_cast<uint32_t>(value & 0xFFFFFFFFLL));
			uint64_t converted_value = (static_cast<uint64_t>(low_part) << 32) | high_part;
			return converted_value;
		}
		else return value;
	}

	int64_t htonll(int64_t value) noexcept
	{
		return ((int64_t)htonll((uint64_t)value));
	}

	int64_t ntohll(int64_t value) noexcept
	{
		return ((int64_t)ntohll((uint64_t)value));
	}

	uint16_t little_endian_to_host(uint16_t value) noexcept
	{
		if constexpr (std::endian::native == std::endian::big)
			return (value >> 8) | (value << 8);
		else return value;
	}

	uint16_t host_to_little_endian(uint16_t value) noexcept
	{
		return little_endian_to_host(value);
	}

	uint32_t little_endian_to_host(uint32_t value) noexcept
	{
		if constexpr (std::endian::native == std::endian::big)
		{
			const uint16_t high_part = little_endian_to_host(static_cast<uint16_t>(value >> 16));
			const uint16_t low_part = little_endian_to_host(static_cast<uint16_t>(value & 0xFFFF));
			uint32_t converted_value = (static_cast<uint32_t>(low_part) << 16) | high_part;
			return converted_value;
		}
		else return value;
	}

	uint32_t host_to_little_endian(uint32_t value) noexcept
	{
		if constexpr (std::endian::native == std::endian::big)
		{
			const uint16_t high_part = host_to_little_endian(static_cast<uint16_t>(value >> 16));
			const uint16_t low_part = host_to_little_endian(static_cast<uint16_t>(value & 0xFFFF));
			uint32_t converted_value = (static_cast<uint32_t>(low_part) << 16) | high_part;
			return converted_value;
		}
		else return value;
	}

	uint64_t little_endian_to_host(uint64_t value) noexcept
	{
		if constexpr (std::endian::native == std::endian::big)
		{
			const uint32_t high_part = little_endian_to_host(static_cast<uint32_t>(value >> 32));
			const uint32_t low_part = little_endian_to_host(static_cast<uint32_t>(value & 0xFFFFFFFFLL));
			uint64_t converted_value = (static_cast<uint64_t>(low_part) << 32) | high_part;
			return converted_value;
		}
		else return value;
	}

	uint64_t host_to_little_endian(uint64_t value) noexcept
	{
		if constexpr (std::endian::native == std::endian::big)
		{
			const uint32_t high_part = host_to_little_endian(static_cast<uint32_t>(value >> 32));
			const uint32_t low_part = host_to_little_endian(static_cast<uint32_t>(value & 0xFFFFFFFFLL));
			uint64_t converted_value = (static_cast<uint64_t>(low_part) << 32) | high_part;
			return converted_value;
		}
		else return value;
	}

	int16_t little_endian_to_host(int16_t value) noexcept
	{
		return ((int16_t)little_endian_to_host((uint16_t)value));
	}

	int16_t host_to_little_endian(int16_t value) noexcept
	{
		return ((int16_t)host_to_little_endian((uint16_t)value));
	}

	int32_t little_endian_to_host(int32_t value) noexcept
	{
		return ((int32_t)little_endian_to_host((uint32_t)value));
	}

	int32_t host_to_little_endian(int32_t value) noexcept
	{
		return ((int32_t)host_to_little_endian((uint32_t)value));
	}

	int64_t little_endian_to_host(int64_t value) noexcept
	{
		return ((int64_t)little_endian_to_host((uint64_t)value));
	}

	int64_t host_to_little_endian(int64_t value) noexcept
	{
		return ((int64_t)host_to_little_endian((uint64_t)value));
	}
}

std::unique_ptr<rfc3489::stun_header> send_stun_3489_request(udp_server &sender, const std::string &stun_host, ip_only_options ip_version_only)
{
	auto udp_version = ip_version_only == ip_only_options::ipv4 ? udp::v4() : udp::v6();
	udp::resolver::resolver_base::flags input_flags = udp::resolver::numeric_service | udp::resolver::v4_mapped | udp::resolver::all_matching;
	if (ip_version_only != ip_only_options::not_set)
		input_flags = udp::resolver::numeric_service | udp::resolver::address_configured;

	asio::error_code ec;
	udp::resolver &udp_resolver = sender.get_resolver();
	udp::resolver::results_type remote_addresses = udp_resolver.resolve(udp_version, stun_host, "3478", input_flags, ec);

	if (ec)
		return nullptr;

	std::vector<udp::endpoint> stun_servers;
	auto [stun_servers_ipv4, stun_servers_ipv6] = split_resolved_addresses(remote_addresses);
	if (!stun_servers_ipv4.empty())
		stun_servers.emplace_back(stun_servers_ipv4.front());
	if (!stun_servers_ipv6.empty())
		stun_servers.emplace_back(stun_servers_ipv4.front());

	auto number = generate_random_number<uint64_t>();
	std::unique_ptr<rfc3489::stun_header> header = rfc3489::create_stun_header(number);
	size_t header_size = sizeof(rfc3489::stun_header);
	for (auto &target_endpoint : stun_servers)
	{
		std::vector<uint8_t> data(header_size);
		std::copy_n((uint8_t *)(header.get()), header_size, data.begin());
		sender.async_send_out(std::move(data), target_endpoint);
	}

	return header;
}

std::unique_ptr<rfc8489::stun_header> send_stun_8489_request(udp_server &sender, const std::string &stun_host, ip_only_options ip_version_only)
{
	auto udp_version = ip_version_only == ip_only_options::ipv4 ? udp::v4() : udp::v6();
	udp::resolver::resolver_base::flags input_flags = udp::resolver::numeric_service | udp::resolver::v4_mapped | udp::resolver::all_matching;
	if (ip_version_only != ip_only_options::not_set)
		input_flags = udp::resolver::numeric_service | udp::resolver::address_configured;

	asio::error_code ec;
	udp::resolver &udp_resolver = sender.get_resolver();
	udp::resolver::results_type remote_addresses = udp_resolver.resolve(udp_version, stun_host, "3478", input_flags, ec);

	if (ec)
		return nullptr;

	std::vector<udp::endpoint> stun_servers;
	auto [stun_servers_ipv4, stun_servers_ipv6] = split_resolved_addresses(remote_addresses);
	if (!stun_servers_ipv4.empty())
		stun_servers.emplace_back(stun_servers_ipv4.front());
	if (!stun_servers_ipv6.empty())
		stun_servers.emplace_back(stun_servers_ipv4.front());

	auto number = generate_random_number<uint64_t>();
	std::unique_ptr<rfc8489::stun_header> header = rfc8489::create_stun_header(number);
	size_t header_size = sizeof(rfc8489::stun_header);
	for (auto &target_endpoint : stun_servers)
	{
		std::vector<uint8_t> data(header_size);
		std::copy_n((uint8_t *)header.get(), header_size, data.data());
		sender.async_send_out(std::move(data), target_endpoint);
	}

	return header;
}

void resend_stun_8489_request(udp_server &sender, const std::string &stun_host, rfc8489::stun_header *header, ip_only_options ip_version_only)
{
	auto udp_version = ip_version_only == ip_only_options::ipv4 ? udp::v4() : udp::v6();
	udp::resolver::resolver_base::flags input_flags = udp::resolver::numeric_service | udp::resolver::v4_mapped | udp::resolver::all_matching;
	if (ip_version_only != ip_only_options::not_set)
		input_flags = udp::resolver::numeric_service | udp::resolver::address_configured;

	asio::error_code ec;
	udp::resolver &udp_resolver = sender.get_resolver();
	udp::resolver::results_type remote_addresses = udp_resolver.resolve(udp_version, stun_host, "3478", input_flags, ec);

	if (ec)
		return;

	std::vector<udp::endpoint> stun_servers;
	auto [stun_servers_ipv4, stun_servers_ipv6] = split_resolved_addresses(remote_addresses);
	if (!stun_servers_ipv4.empty())
		stun_servers.emplace_back(stun_servers_ipv4.front());
	if (!stun_servers_ipv6.empty())
		stun_servers.emplace_back(stun_servers_ipv4.front());

	size_t header_size = sizeof(rfc8489::stun_header);
	for (auto &target_endpoint : stun_servers)
	{
		std::vector<uint8_t> data(header_size);
		std::copy_n((uint8_t *)header, header_size, data.data());
		sender.async_send_out(std::move(data), target_endpoint);
	}

	return;
}

int64_t time_gap_of_ingress_receive(udp_mappings *ptr)
{
	return calculate_difference(right_now(), ptr->last_ingress_receive_time.load());
}

int64_t time_gap_of_ingress_send(udp_mappings *ptr)
{
	return calculate_difference(right_now(), ptr->last_inress_send_time.load());
}

int64_t time_gap_of_egress_receive(udp_mappings *ptr)
{
	return calculate_difference(right_now(), ptr->last_egress_receive_time.load());
}

int64_t time_gap_of_egress_send(udp_mappings *ptr)
{
	return calculate_difference(right_now(), ptr->last_inress_send_time.load());
}


void udp_server::continue_receive()
{
	start_receive();
}

void udp_server::async_send_out(std::unique_ptr<std::vector<uint8_t>> data, udp::endpoint client_endpoint)
{
	if (data == nullptr)
		return;
	std::vector<uint8_t> &buffer = *data;
	connection_socket.async_send_to(asio::buffer(buffer), client_endpoint,
		[data_ = std::move(data)](const asio::error_code &error, size_t bytes_transferred) {});
}

void udp_server::async_send_out(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer_endpoint)
{
	if (data == nullptr)
		return;
	uint8_t *buffer_raw_ptr = data.get();
	connection_socket.async_send_to(asio::buffer(buffer_raw_ptr, data_size), peer_endpoint,
		[data_ = std::move(data)](const asio::error_code &error, size_t bytes_transferred) {});
}

void udp_server::async_send_out(std::unique_ptr<uint8_t[]> data, const uint8_t *data_ptr, size_t data_size, udp::endpoint client_endpoint)
{
	if (data == nullptr)
		return;
	connection_socket.async_send_to(asio::buffer(data_ptr, data_size), client_endpoint,
		[data_ = std::move(data)](const asio::error_code &error, size_t bytes_transferred) {});
}

void udp_server::async_send_out(std::vector<uint8_t> &&data, udp::endpoint client_endpoint)
{
	auto asio_buffer = asio::buffer(data);
	connection_socket.async_send_to(asio_buffer, client_endpoint,
		[data_ = std::move(data)](const asio::error_code &error, size_t bytes_transferred) {});
}

void udp_server::async_send_out(std::vector<uint8_t> &&data, const uint8_t *data_ptr, size_t data_size, udp::endpoint client_endpoint)
{
	auto asio_buffer = asio::buffer(data_ptr, data_size);
	connection_socket.async_send_to(asio_buffer, client_endpoint,
		[data_ = std::move(data)](const asio::error_code &error, size_t bytes_transferred) {});
}


void udp_server::initialise(udp::endpoint ep)
{
	asio::ip::v6_only v6_option(ip_version_only == ip_only_options::ipv6);
	connection_socket.open(ep.protocol());
	if (ep.address().is_v6())
		connection_socket.set_option(v6_option);
	connection_socket.bind(ep);
}

void udp_server::start_receive()
{
	std::unique_ptr<uint8_t[]> buffer_cache = std::make_unique<uint8_t[]>(BUFFER_SIZE);
	uint8_t *buffer_raw_ptr = buffer_cache.get();
	connection_socket.async_receive_from(asio::buffer(buffer_raw_ptr, BUFFER_SIZE), incoming_endpoint,
		[data = std::move(buffer_cache), this](const asio::error_code &error, std::size_t bytes_transferred) mutable
		{
			handle_receive(std::move(data), error, bytes_transferred);
		});
}

void udp_server::handle_receive(std::unique_ptr<uint8_t[]> buffer_cache, const asio::error_code &error, std::size_t bytes_transferred)
{
	if (error)
	{
		if (!connection_socket.is_open())
			return;
	}

	udp::endpoint copy_of_incoming_endpoint = incoming_endpoint;
	start_receive();

	if (buffer_cache == nullptr || bytes_transferred == 0)
		return;

	if (BUFFER_SIZE - bytes_transferred < BUFFER_EXPAND_SIZE)
	{
		std::unique_ptr<uint8_t[]> new_buffer = std::make_unique<uint8_t[]>(BUFFER_SIZE + BUFFER_EXPAND_SIZE);
		std::copy_n(buffer_cache.get(), bytes_transferred, new_buffer.get());
		buffer_cache.swap(new_buffer);
	}

	if (sequence_task_pool != nullptr)
	{
		size_t pointer_to_number = (size_t)this;
		if (task_limit > 0 && sequence_task_pool->get_task_count(pointer_to_number) > task_limit)
			return;
		sequence_task_pool->push_task(pointer_to_number, [this, bytes_transferred, copy_of_incoming_endpoint](std::unique_ptr<uint8_t[]> data) mutable
			{ callback(std::move(data), bytes_transferred, copy_of_incoming_endpoint, port_number); },
			std::move(buffer_cache));
	}
	else
	{
		callback(std::move(buffer_cache), bytes_transferred, copy_of_incoming_endpoint, port_number);
	}
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
	stopped.store(true);
	callback = empty_udp_callback;
	if (connection_socket.is_open())
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
	auto udp_version = ip_version_only == ip_only_options::ipv4 ? udp::v4() : udp::v6();
	udp::resolver::resolver_base::flags input_flags = udp::resolver::numeric_service | udp::resolver::v4_mapped | udp::resolver::all_matching;
	if (ip_version_only != ip_only_options::not_set)
		input_flags = udp::resolver::numeric_service | udp::resolver::address_configured;

	return resolver.resolve(udp_version, remote_address, port_num, input_flags, ec);
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

size_t udp_client::send_out(const std::vector<uint8_t> &data, udp::endpoint peer_endpoint, asio::error_code &ec)
{
	if (stopped.load())
		return 0;

	size_t sent_size = connection_socket.send_to(asio::buffer(data), peer_endpoint, 0, ec);
	last_send_time.store(right_now());
	return sent_size;
}

size_t udp_client::send_out(const uint8_t *data, size_t size, udp::endpoint peer_endpoint, asio::error_code &ec)
{
	if (stopped.load() || data == nullptr)
		return 0;

	size_t sent_size = connection_socket.send_to(asio::buffer(data, size), peer_endpoint, 0, ec);
	last_send_time.store(right_now());
	return sent_size;
}

void udp_client::async_send_out(std::unique_ptr<std::vector<uint8_t>> data, udp::endpoint peer_endpoint)
{
	if (stopped.load() || data == nullptr)
		return;

	std::vector<uint8_t> &buffer = *data;
	connection_socket.async_send_to(asio::buffer(buffer), peer_endpoint,
		[data_ = std::move(data)](const asio::error_code &error, size_t bytes_transferred) {});
	last_send_time.store(right_now());
}

void udp_client::async_send_out(std::unique_ptr<uint8_t[]> data, size_t data_size, udp::endpoint peer_endpoint)
{
	if (stopped.load() || data == nullptr)
		return;

	uint8_t *buffer_raw_ptr = data.get();
	connection_socket.async_send_to(asio::buffer(buffer_raw_ptr, data_size), peer_endpoint,
		[data_ = std::move(data)](const asio::error_code &error, size_t bytes_transferred) {});
	last_send_time.store(right_now());
}

void udp_client::async_send_out(std::unique_ptr<uint8_t[]> data, const uint8_t *data_ptr, size_t data_size, udp::endpoint client_endpoint)
{
	if (data == nullptr || data_ptr == nullptr)
		return;
	connection_socket.async_send_to(asio::buffer(data_ptr, data_size), client_endpoint,
		[data_ = std::move(data)](const asio::error_code &error, size_t bytes_transferred) {});
	last_send_time.store(right_now());
}

void udp_client::async_send_out(std::vector<uint8_t> &&data, udp::endpoint peer_endpoint)
{
	if (stopped.load())
		return;

	auto asio_buffer = asio::buffer(data);
	connection_socket.async_send_to(asio_buffer, peer_endpoint,
		[data_ = std::move(data)](const asio::error_code &error, size_t bytes_transferred) {});
	last_send_time.store(right_now());
}

void udp_client::async_send_out(std::vector<uint8_t> &&data, const uint8_t *data_ptr, size_t data_size, udp::endpoint client_endpoint)
{
	if (stopped.load())
		return;

	auto asio_buffer = asio::buffer(data_ptr, data_size);
	connection_socket.async_send_to(asio_buffer, client_endpoint,
		[data_ = std::move(data)](const asio::error_code &error, size_t bytes_transferred) {});
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
	if (ip_version_only == ip_only_options::ipv4)
	{
		connection_socket.open(udp::v4());
	}
	else
	{
		asio::ip::v6_only v6_option(ip_version_only == ip_only_options::ipv6);
		connection_socket.open(udp::v6());
		connection_socket.set_option(v6_option);
	}
}

void udp_client::start_receive()
{
	if (paused.load() || stopped.load())
		return;

	std::unique_ptr<uint8_t[]> buffer_cache = std::make_unique<uint8_t[]>(BUFFER_SIZE);
	uint8_t *buffer_raw_ptr = buffer_cache.get();
	connection_socket.async_receive_from(asio::buffer(buffer_raw_ptr, BUFFER_SIZE), incoming_endpoint,
		[buffer = std::move(buffer_cache), this](const asio::error_code &error, std::size_t bytes_transferred) mutable
		{
			handle_receive(std::move(buffer), error, bytes_transferred);
		});
}

void udp_client::handle_receive(std::unique_ptr<uint8_t[]> buffer_cache, const asio::error_code &error, std::size_t bytes_transferred)
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

	if (buffer_cache == nullptr || bytes_transferred == 0)
		return;

	if (BUFFER_SIZE - bytes_transferred < BUFFER_EXPAND_SIZE)
	{
		std::unique_ptr<uint8_t[]> new_buffer = std::make_unique<uint8_t[]>(BUFFER_SIZE + BUFFER_EXPAND_SIZE);
		std::copy_n(buffer_cache.get(), bytes_transferred, new_buffer.get());
		buffer_cache.swap(new_buffer);
	}
	
	if (sequence_task_pool != nullptr)
	{
		size_t pointer_to_number = (size_t)this;
		if (task_limit > 0 && sequence_task_pool->get_task_count(pointer_to_number) > task_limit)
			return;
		sequence_task_pool->push_task(pointer_to_number, [this, bytes_transferred, copy_of_incoming_endpoint](std::unique_ptr<uint8_t[]> data) mutable
			{ callback(std::move(data), bytes_transferred, copy_of_incoming_endpoint, 0); },
			std::move(buffer_cache));
	}
	else
	{
		callback(std::move(buffer_cache), bytes_transferred, copy_of_incoming_endpoint, 0);
	}
}
