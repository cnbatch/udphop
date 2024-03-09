#pragma once

#ifndef _SHARE_DEFINES_
#define _SHARE_DEFINES_

#include <atomic>
#include <cstdint>
#include <vector>
#include <string>
#include <string_view>
#include <map>
#include <random>
#include <filesystem>
#include "aead.hpp"

constexpr std::string_view app_name = "udphop";

enum class running_mode { unknow, empty, server, client, relay, relay_ingress, relay_egress };
enum class encryption_mode { unknow, empty, none, aes_gcm, aes_ocb, chacha20, xchacha20 };
namespace constant_values
{
	constexpr uint16_t dport_refresh_default = 60;
	constexpr uint16_t dport_refresh_minimal = 20;
	constexpr uint16_t default_timeout = 1800;	// second
	constexpr int iv_checksum_block_size = 2;
	constexpr int encryption_block_reserve = 48;
	constexpr int fec_container_header = 2;
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
	uint16_t listen_port = 0;
	uint16_t listen_port_start = 0;
	uint16_t listen_port_end = 0;
	uint16_t destination_port = 0;
	uint16_t destination_port_start = 0;
	uint16_t destination_port_end = 0;
	uint16_t dynamic_port_refresh = constant_values::dport_refresh_default;	// seconds
	uint16_t keep_alive = 0;	// seconds
	uint16_t timeout = 0;	 // seconds
	uint8_t fec_data = 0;
	uint8_t fec_redundant = 0;
	encryption_mode encryption = encryption_mode::empty;
	running_mode mode = running_mode::empty;
	bool ipv4_only = false;
	std::string listen_on;
	std::string destination_address;
	std::string encryption_password;
	std::string stun_server;
	std::filesystem::path log_directory;
	std::filesystem::path log_ip_address;
	std::filesystem::path log_messages;
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

user_settings parse_from_args(const std::vector<std::string> &args, std::vector<std::string> &error_msg);

uint16_t generate_new_port_number(uint16_t start_port_num, uint16_t end_port_num);
uint32_t generate_token_number();

int64_t calculate_difference(int64_t number1, int64_t number2);
std::string time_to_string();
std::string time_to_string_with_square_brackets();
void print_ip_to_file(const std::string &message, const std::filesystem::path &log_file);
void print_message_to_file(const std::string &message, const std::filesystem::path &log_file);

#endif // !_SHARE_HEADER_
