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
