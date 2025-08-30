#pragma once

#ifndef _SHARE_DEFINES_
#define _SHARE_DEFINES_

#include <atomic>
#include <algorithm>
#include <cstdint>
#include <vector>
#include <string>
#include <string_view>
#include <set>
#include <map>
#include <random>
#include <filesystem>
#include <type_traits>
#include <concepts>
#include <ranges>
#include <thread>
#ifdef __cpp_lib_format
#include <format>
#endif
#include "aead.hpp"
#include "../3rd_party/task_thread_pool.hpp"

#ifdef __linux__	
constexpr bool linux_system = true;
#else
constexpr bool linux_system = false;
#endif

constexpr std::string_view app_name = "udphop";
constexpr std::string_view app_version = "20250830";

enum class running_mode { unknow, empty, server, client, relay, relay_ingress, relay_egress };
enum class encryption_mode { unknow, empty, none, plain_xor, aes_gcm, aes_ocb, chacha20, xchacha20 };
enum class ip_only_options : unsigned short { not_set = 0, ipv4 = 1, ipv6 = 2 };

namespace constant_values
{
	constexpr uint16_t dport_refresh_default = 60;
	constexpr uint16_t dport_refresh_minimal = 20;
	constexpr uint16_t default_timeout = 1800;	// second
	constexpr int iv_checksum_block_size = 2;
	constexpr int encryption_block_reserve = 48;
	constexpr int fec_container_header = 2;
}

inline constexpr ip_only_options
operator&(ip_only_options option_1, ip_only_options option_2)
{
	return static_cast<ip_only_options>(static_cast<uint8_t>(option_1) & static_cast<uint8_t>(option_2));
}

inline constexpr ip_only_options
operator|(ip_only_options option_1, ip_only_options option_2)
{
	return static_cast<ip_only_options>(static_cast<uint8_t>(option_1) | static_cast<uint8_t>(option_2));
}

inline constexpr ip_only_options
operator^(ip_only_options option_1, ip_only_options option_2)
{
	return static_cast<ip_only_options>(static_cast<uint8_t>(option_1) ^ static_cast<uint8_t>(option_2));
}

inline constexpr ip_only_options
operator~(ip_only_options input_option)
{
	return static_cast<ip_only_options>(~static_cast<int>(input_option));
}

inline ip_only_options &
operator&=(ip_only_options &option_1, ip_only_options option_2)
{
	option_1 = option_1 & option_2;
	return option_1;
}

inline ip_only_options &
operator|=(ip_only_options &option_1, ip_only_options option_2)
{
	option_1 = option_1 | option_2;
	return option_1;
}

inline ip_only_options &
operator^=(ip_only_options &option_1, ip_only_options option_2)
{
	option_1 = option_1 ^ option_2;
	return option_1;
}

template<typename T>
T generate_random_number()
{
	thread_local std::mt19937 mt(std::random_device{}());
	std::uniform_int_distribution<T> uniform_dist(std::numeric_limits<T>::min(), std::numeric_limits<T>::max());
	return uniform_dist(mt);
}


struct user_settings
{
	uint16_t dynamic_port_refresh = constant_values::dport_refresh_default;	// seconds
	uint16_t keep_alive = 0;	// seconds
	uint16_t timeout = 0;	 // seconds
	uint8_t fec_original_packet_count = 0;
	uint8_t fec_redundant_packet_count = 0;
	encryption_mode encryption = encryption_mode::empty;
	running_mode mode = running_mode::empty;
	ip_only_options ip_version_only = ip_only_options::not_set;
	std::vector<std::string> listen_on;
	std::vector<uint16_t> listen_ports;
	std::vector<uint16_t> destination_ports;
	std::vector<std::string> destination_address_list;
	std::string destination_dnstxt;
	std::string encryption_password;
	std::string stun_server;
	std::string update_ipv4_path;
	std::string update_ipv6_path;
	std::filesystem::path log_directory;
	std::filesystem::path log_ip_address;
	std::filesystem::path log_messages;
	std::filesystem::path log_status;
	std::string config_filename;
	std::shared_ptr<user_settings> ingress;
	std::shared_ptr<user_settings> egress;
};

struct status_records
{
	alignas(64) std::atomic<size_t> ingress_raw_traffic;
	alignas(64) std::atomic<size_t> ingress_raw_traffic_each_second;
	alignas(64) std::atomic<size_t> ingress_raw_traffic_peak;
	alignas(64) std::atomic<size_t> ingress_raw_traffic_valley;
	alignas(64) std::atomic<size_t> egress_raw_traffic;
	alignas(64) std::atomic<size_t> egress_raw_traffic_each_second;
	alignas(64) std::atomic<size_t> egress_raw_traffic_peak;
	alignas(64) std::atomic<size_t> egress_raw_traffic_valley;
	alignas(64) std::atomic<size_t> fec_recovery_count;
	alignas(64) std::atomic<size_t> fec_raw_packet_count;
	alignas(64) std::atomic<size_t> fec_raw_redund_count;
};

class traffic_pv_records
{
public:
	std::vector<size_t> ingress_traffic_counter;
	std::vector<size_t> egress_traffic_counter;
};

#pragma pack (push, 1)
struct fec_container
{
	uint16_t data_length;
	uint8_t data[1];
};
#pragma pack(pop)

user_settings parse_from_args(const std::vector<std::string> &args, std::vector<std::string> &error_msg);
std::set<uint16_t> port_range_to_vector(const std::string &input_str, std::vector<std::string> &error_msg, const std::string &acting_role);
std::vector<uint16_t> string_to_port_numbers(const std::string& input_str, std::vector<std::string>& error_msg, const std::string& acting_role);
std::vector<std::string> string_to_address_list(const std::string &input_str);
bool is_continuous(const std::vector<uint16_t> &numbers);

uint16_t generate_new_port_number(uint16_t start_port_num, uint16_t end_port_num);
uint16_t generate_new_port_number(const std::vector<uint16_t> &port_list);
uint32_t generate_token_number();
size_t randomly_pick_index(size_t container_size);

template<typename T>
T calculate_difference(T number_left, T number_right)
{
	return std::abs(number_left - number_right);
}

template <typename T>
struct is_std_shared_ptr : std::false_type {};
template <typename T>
struct is_std_shared_ptr<std::shared_ptr<T>> : std::true_type {};

#ifdef __cpp_lib_atomic_shared_ptr
template <typename T>
struct is_atomic_shared_ptr : std::false_type {};
template <typename T>
struct is_atomic_shared_ptr<std::atomic<T>> : is_std_shared_ptr<T> {};

template <typename T>
concept IsAtomicSharedPtr = is_atomic_shared_ptr<std::remove_cvref_t<T>>::value;

template <typename PtrT>
	requires IsAtomicSharedPtr<PtrT>
auto load_atomic_ptr(PtrT &ptr)
{
	return ptr.load();
}
#else
template <typename T>
concept IsStdSharedPtr = is_std_shared_ptr<std::remove_cvref_t<T>>::value;

template <typename PtrT>
	requires IsStdSharedPtr<PtrT>
auto load_atomic_ptr(PtrT &ptr)
{
	return std::atomic_load(&ptr);
}
#endif


std::string time_to_string();
std::string time_to_string_with_square_brackets();
void print_ip_to_file(const std::string &message, const std::filesystem::path &log_file);
void print_message_to_file(const std::string &message, const std::filesystem::path &log_file);
void print_status_to_file(const std::string &message, const std::filesystem::path &log_file);
std::string to_speed_unit(size_t value, size_t duration_seconds);

#endif // !_SHARE_HEADER_
