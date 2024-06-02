#include <climits>
#include <stdexcept>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <mutex>
#include "share_defines.hpp"
#include "configurations.hpp"
#include "string_utils.hpp"
#ifdef __cpp_lib_format
#include <format>
#endif


user_settings parse_from_args(const std::vector<std::string> &args, std::vector<std::string> &error_msg)
{
	user_settings current_user_settings;
	error_msg.clear();

	if (std::vector<std::string> error_messages = parse_running_mode(args, current_user_settings);
		!error_messages.empty())
	{
		error_msg.insert(error_msg.end(),
			std::make_move_iterator(error_messages.begin()),
			std::make_move_iterator(error_messages.end())
		);
		return current_user_settings;
	}

	if (std::vector<std::string> error_messages = parse_the_rest(args, current_user_settings);
		!error_messages.empty())
	{
		error_msg.insert(error_msg.end(),
			std::make_move_iterator(error_messages.begin()),
			std::make_move_iterator(error_messages.end())
		);
		return current_user_settings;
	}

	check_settings(current_user_settings, error_msg);

	return current_user_settings;

	//return parse_settings(args, error_msg);
}

uint16_t generate_new_port_number(uint16_t start_port_num, uint16_t end_port_num)
{
	thread_local std::mt19937 mt(std::random_device{}());
	std::uniform_int_distribution<uint16_t> uniform_dist(start_port_num, end_port_num);
	return uniform_dist(mt);
}

uint32_t generate_token_number()
{
	thread_local std::mt19937 mt(std::random_device{}());
	std::uniform_int_distribution<uint32_t> uniform_dist(32, std::numeric_limits<uint32_t>::max() - 1);
	return uniform_dist(mt);
}

int64_t calculate_difference(int64_t number1, int64_t number2)
{
	return std::abs(number1 - number2);
}

std::vector<uint8_t> create_raw_random_data(size_t mtu_size)
{
	std::vector<uint8_t> temp_array(mtu_size, 0);
	uint8_t *ptr = temp_array.data() + (mtu_size / 2);
	uint64_t *ptr_force_uint64_t = reinterpret_cast<uint64_t*>(ptr);
	*ptr_force_uint64_t = generate_random_number<uint64_t>();
	return temp_array;
}


std::string time_to_string()
{
	std::time_t t = std::time(nullptr);
	std::tm tm = *std::localtime(&t);
	std::ostringstream oss;
	oss << std::put_time(&tm, "%F %T %z");
	return oss.str();
}

std::string time_to_string_with_square_brackets()
{
	return "[" + time_to_string() + "] ";
}

void print_ip_to_file(const std::string &message, const std::filesystem::path &log_file)
{
	if (log_file.empty())
		return;

	static std::ofstream output_file{};
	static std::mutex mtx;
	std::unique_lock locker{ mtx };
	output_file.open(log_file, std::ios::out | std::ios::trunc);
	if (output_file.is_open() && output_file.good())
		output_file << message;
	output_file.close();
}

void print_message_to_file(const std::string &message, const std::filesystem::path &log_file)
{
	if (log_file.empty())
		return;

	static std::ofstream output_file{};
	static std::mutex mtx;
	std::unique_lock locker{ mtx };
	output_file.open(log_file, std::ios::out | std::ios::app);
	if (output_file.is_open() && output_file.good())
		output_file << message;
	output_file.close();
}

void print_status_to_file(const std::string & message, const std::filesystem::path & log_file)
{
	if (log_file.empty())
		return;

	static std::ofstream output_file{};
	static std::mutex mtx;
	std::unique_lock locker{ mtx };
	output_file.open(log_file, std::ios::out | std::ios::trunc);
	if (output_file.is_open() && output_file.good())
		output_file << message;
	output_file.close();
}
