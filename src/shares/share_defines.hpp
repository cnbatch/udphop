#pragma once

#ifndef _SHARE_DEFINES_
#define _SHARE_DEFINES_

#include <atomic>
#include <cstdint>
#include <vector>
#include <string>
#include <string_view>
#include <set>
#include <map>
#include <random>
#include <filesystem>
#ifdef __cpp_lib_format
#include <format>
#endif
#include "aead.hpp"
#include "../3rd_party/thread_pool.hpp"

constexpr std::string_view app_name = "udphop";

enum class running_mode { unknow, empty, server, client, relay, relay_ingress, relay_egress };
enum class encryption_mode { unknow, empty, none, aes_gcm, aes_ocb, chacha20, xchacha20 };
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
	uint8_t fec_data = 0;
	uint8_t fec_redundant = 0;
	encryption_mode encryption = encryption_mode::empty;
	running_mode mode = running_mode::empty;
	ip_only_options ip_version_only = ip_only_options::not_set;
	std::vector<std::string> listen_on;
	std::vector<uint16_t> listen_ports;
	std::vector<uint16_t> destination_ports;
	std::vector<std::string> destination_address_list;
	std::string encryption_password;
	std::string stun_server;
	std::filesystem::path log_directory;
	std::filesystem::path log_ip_address;
	std::filesystem::path log_messages;
	std::filesystem::path log_status;
	std::string config_filename;
	std::shared_ptr<user_settings> ingress;
	std::shared_ptr<user_settings> egress;
};

#pragma pack (push, 1)
struct fec_container
{
	uint16_t data_length;
	uint8_t data[1];
};
#pragma pack(pop)

struct task_pool_colloector
{
	ttp::task_thread_pool *parallel_encryption_pool;
	ttp::task_thread_pool *parallel_decryption_pool;
	ttp::task_thread_pool *listener_parallels;
	ttp::task_thread_pool *forwarder_parallels;
};

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

std::string time_to_string();
std::string time_to_string_with_square_brackets();
void print_ip_to_file(const std::string &message, const std::filesystem::path &log_file);
void print_message_to_file(const std::string &message, const std::filesystem::path &log_file);
void print_status_to_file(const std::string &message, const std::filesystem::path &log_file);

#endif // !_SHARE_HEADER_
