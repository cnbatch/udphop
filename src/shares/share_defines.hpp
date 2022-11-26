#pragma once

#ifndef _SHARE_DEFINES_
#define _SHARE_DEFINES_

#include <atomic>
#include <cstdint>
#include <vector>
#include <string>
#include <map>
#include <random>
#include <filesystem>
#include "aes-256.hpp"

enum class running_mode { unknow, empty, server, client };
enum class encryption_mode { unknow, empty, none, aes_gcm, aes_ocb };
constexpr uint16_t dport_refresh_default = 60;
constexpr uint16_t dport_refresh_minimal = 20;

template<typename T>
T generate_random_number()
{
	std::random_device rd;
	std::mt19937 mt(rd());
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
	uint16_t dynamic_port_refresh = dport_refresh_default;	// seconds
	encryption_mode encryption = encryption_mode::empty;
	running_mode mode = running_mode::empty;
	std::string listen_on;
	std::string destination_address;
	std::string encryption_password;
	std::string stun_server;
	std::filesystem::path log_directory;
	std::filesystem::path log_ip_address;
};

user_settings parse_from_args(const std::vector<std::string> &args, std::vector<std::string> &error_msg);
void check_settings(user_settings &current_user_settings, std::vector<std::string> &error_msg);

int64_t calculate_difference(int64_t number1, int64_t number2);
std::vector<uint8_t> create_raw_random_data(size_t mtu_size);
std::pair<std::string, size_t> encrypt_data(const std::string &password, encryption_mode mode, uint8_t *data_ptr, int length);
std::vector<uint8_t> encrypt_data(const std::string &password, encryption_mode mode, const void *data_ptr, int length, std::string &error_message);
std::vector<uint8_t> encrypt_data(const std::string &password, encryption_mode mode, std::vector<uint8_t> &&plain_data, std::string &error_message);
std::pair<std::string, size_t> decrypt_data(const std::string &password, encryption_mode mode, uint8_t *data_ptr, int length);
std::vector<uint8_t> decrypt_data(const std::string &password, encryption_mode mode, const void *data_ptr, int length, std::string &error_message);
std::vector<uint8_t> decrypt_data(const std::string &password, encryption_mode mode, std::vector<uint8_t> &&cipher_data, std::string &error_message);
void xor_forward(uint8_t *data, size_t data_size);
void xor_forward(std::vector<uint8_t> &data);
void xor_backward(uint8_t *data, size_t data_size);
void xor_backward(std::vector<uint8_t> &data);
void bitwise_not(uint8_t *input_data, size_t length);

void print_message_to_file(const std::string &message, const std::filesystem::path &log_file);

#endif // !_SHARE_HEADER_
