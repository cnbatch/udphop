#pragma once
#include "share_defines.hpp"
#include <asio.hpp>

#ifndef __DATA_OPERATIONS_HPP__
#define __DATA_OPERATIONS_HPP__

std::vector<uint8_t> create_raw_random_data(size_t mtu_size);
std::vector<uint8_t> create_empty_data(const std::string &password, encryption_mode mode, size_t mtu_size);
std::pair<std::string, size_t> encrypt_data(const std::string &password, encryption_mode mode, uint8_t *data_ptr, int length);
std::vector<uint8_t> encrypt_data(const std::string &password, encryption_mode mode, const void *data_ptr, int length, std::string &error_message);
std::vector<uint8_t> encrypt_data(const std::string &password, encryption_mode mode, std::vector<uint8_t> &&plain_data, std::string &error_message);
std::pair<std::string, size_t> decrypt_data(const std::string &password, encryption_mode mode, uint8_t *data_ptr, int length);
std::vector<uint8_t> decrypt_data(const std::string &password, encryption_mode mode, const void *data_ptr, int length, std::string &error_message);
std::vector<uint8_t> decrypt_data(const std::string &password, encryption_mode mode, std::vector<uint8_t> &&cipher_data, std::string &error_message);
std::pair<std::unique_ptr<uint8_t[]>, size_t> clone_into_pair(const uint8_t *original, size_t data_size);
const std::map<size_t, const uint8_t*> mapped_pair_to_mapped_pointer(const std::map<size_t, std::pair<std::unique_ptr<uint8_t[]>, size_t>> &mapped_container);
std::tuple<std::unique_ptr<uint8_t[]>, size_t, size_t> compact_into_container(const std::vector<std::pair<std::unique_ptr<uint8_t[]>, size_t>> &fec_snd_data_cache);
std::pair<std::map<size_t, std::pair<std::unique_ptr<uint8_t[]>, size_t>>, size_t> compact_into_container(const std::map<uint16_t, std::pair<std::unique_ptr<uint8_t[]>, size_t>> &fec_rcv_data_cache, size_t data_max_count);
std::vector<std::vector<uint8_t>> extract_from_container(const std::vector<std::vector<uint8_t>> &recovered_container);
std::vector<uint8_t> copy_from_container(const std::vector<uint8_t> &recovered_container);
std::pair<uint8_t*, size_t> extract_from_container(const std::vector<uint8_t> &recovered_container);

class async_cipher_operations
{
private:
	task_thread_pool::task_thread_pool &parallel_pool;
	const std::string password;
	encryption_mode mode;

public:
	async_cipher_operations() = delete;
	async_cipher_operations(task_thread_pool::task_thread_pool &parallel_pool, std::string password, encryption_mode mode):
		parallel_pool(parallel_pool), password(password), mode(mode) {};
	asio::awaitable<std::pair<std::string, size_t>> async_encrypt(asio::io_context &ioc, uint8_t *data_ptr, int length);
	asio::awaitable<std::vector<uint8_t>> async_encrypt(asio::io_context &ioc, const void *data_ptr, int length, std::string &error_message);
	asio::awaitable<std::vector<uint8_t>> async_encrypt(asio::io_context &ioc, std::vector<uint8_t> &&plain_data, std::string &error_message);
	asio::awaitable<std::pair<std::string, size_t>> async_decrypt(asio::io_context &ioc, uint8_t *data_ptr, int length);
	asio::awaitable<std::vector<uint8_t>> async_decrypt(asio::io_context &ioc, const void *data_ptr, int length, std::string &error_message);
	asio::awaitable<std::vector<uint8_t>> async_decrypt(asio::io_context &ioc, std::vector<uint8_t> &&cipher_data, std::string &error_message);
};

#endif	// !__DATA_OPERATIONS_HPP__