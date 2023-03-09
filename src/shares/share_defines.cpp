#include <climits>
#include <stdexcept>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <mutex>
#include "share_defines.hpp"
#include "string_utils.hpp"


user_settings parse_from_args(const std::vector<std::string> &args, std::vector<std::string> &error_msg)
{
	using namespace str_utils;

	user_settings current_user_settings;
	error_msg.clear();

	for (const std::string &arg : args)
	{
		auto line = trim_copy(arg);
		if (line.empty() || line[0] == '#')
			continue;
		auto eq = line.find_first_of("=");
		if (eq == std::string::npos) continue;

		std::string name = line.substr(0, eq);
		std::string value = line.substr(eq + 1);
		trim(name);
		trim(value);
		std::string original_value = value;
		to_lower(name);
		to_lower(value);

		if (value.empty())
			continue;

		try
		{
			switch (strhash(name.c_str()))
			{
			case strhash("mode"):
				switch (strhash(value.c_str()))
				{
				case strhash("server"):
					current_user_settings.mode = running_mode::server;
					break;
				case strhash("client"):
					current_user_settings.mode = running_mode::client;
					break;
				default:
					current_user_settings.mode = running_mode::unknow;
					error_msg.emplace_back("invalid mode: " + value);
					break;
				}
				break;

			case strhash("listen_on"):
				current_user_settings.listen_on = original_value;
				break;

			case strhash("listen_port"):
				if (auto pos = value.find("-"); pos == std::string::npos)
				{
					if (auto port_number = std::stoi(value); port_number > 0 && port_number < USHRT_MAX)
						current_user_settings.listen_port = static_cast<uint16_t>(port_number);
					else
						error_msg.emplace_back("invalid listen_port number: " + value);
				}
				else
				{
					std::string start_port = value.substr(0, pos);
					std::string end_port = value.substr(pos + 1);
					trim(start_port);
					trim(end_port);

					if (start_port.empty() || end_port.empty())
					{
						error_msg.emplace_back("invalid listen_port range: " + value);
						break;
					}

					if (auto port_number = std::stoi(start_port); port_number > 0 && port_number < USHRT_MAX)
						current_user_settings.listen_port_start = static_cast<uint16_t>(port_number);
					else
						error_msg.emplace_back("invalid listen_port_start number: " + start_port);

					if (auto port_number = std::stoi(end_port); port_number > 0 && port_number < USHRT_MAX)
						current_user_settings.listen_port_end = static_cast<uint16_t>(port_number);
					else
						error_msg.emplace_back("invalid listen_port_end number: " + end_port);
				}
				break;

			case strhash("dport_refresh"):	// client only
				if (auto time_interval = std::stoi(value); time_interval < DPORT_REFRESH_MINIMAL)
					current_user_settings.dynamic_port_refresh = DPORT_REFRESH_MINIMAL;
				else if (time_interval >= DPORT_REFRESH_MINIMAL && time_interval < USHRT_MAX)
					current_user_settings.dynamic_port_refresh = static_cast<uint16_t>(time_interval);
				else
					current_user_settings.dynamic_port_refresh = USHRT_MAX;
				break;

			case strhash("destination_port"):
				if (auto pos = value.find("-"); pos == std::string::npos)
				{
					if (auto port_number = std::stoi(value); port_number > 0 && port_number < 65536)
						current_user_settings.destination_port = static_cast<uint16_t>(port_number);
					else
						error_msg.emplace_back("invalid listen_port number: " + value);
				}
				else
				{
					std::string start_port = value.substr(0, pos);
					std::string end_port = value.substr(pos + 1);
					trim(start_port);
					trim(end_port);

					if (start_port.empty() || end_port.empty())
					{
						error_msg.emplace_back("invalid destination_port range: " + value);
						break;
					}

					if (auto port_number = std::stoi(start_port); port_number > 0 && port_number < USHRT_MAX)
						current_user_settings.destination_port_start = static_cast<uint16_t>(port_number);
					else
						error_msg.emplace_back("invalid destination_port_start number: " + start_port);

					if (auto port_number = std::stoi(end_port); port_number > 0 && port_number < USHRT_MAX)
						current_user_settings.destination_port_end = static_cast<uint16_t>(port_number);
					else
						error_msg.emplace_back("invalid destination_port_end number: " + end_port);
				}
				break;


			case strhash("destination_address"):
				current_user_settings.destination_address = value;
				break;

			case strhash("encryption_password"):
				current_user_settings.encryption_password = original_value;
				break;

			case strhash("encryption_algorithm"):
				switch (strhash(value.c_str()))
				{
				case strhash("none"):
					current_user_settings.encryption = encryption_mode::none;
					break;
				case strhash("aes-gcm"):
					current_user_settings.encryption = encryption_mode::aes_gcm;
					break;
				case strhash("aes-ocb"):
					current_user_settings.encryption = encryption_mode::aes_ocb;
					break;
				case strhash("chacha20"):
					current_user_settings.encryption = encryption_mode::chacha20;
					break;
				case strhash("xchacha20"):
					current_user_settings.encryption = encryption_mode::xchacha20;
					break;
				default:
					current_user_settings.encryption = encryption_mode::unknow;
					error_msg.emplace_back("encryption_algorithm is incorrect: " + value);
					break;
				}
				break;

			case strhash("timeout"):
				if (auto time_interval = std::stoi(value); time_interval <= 0 || time_interval > USHRT_MAX)
					current_user_settings.timeout = 0;
				else
					current_user_settings.timeout = static_cast<uint16_t>(time_interval);
				break;

			case strhash("keep_alive"):
				if (auto time_interval = std::stoi(value); time_interval <= 0)
					current_user_settings.keep_alive = 0;
				else if (time_interval > 0 && time_interval < USHRT_MAX)
					current_user_settings.keep_alive = static_cast<uint16_t>(time_interval);
				else
					current_user_settings.keep_alive = USHRT_MAX;
				break;

			case strhash("stun_server"):
				current_user_settings.stun_server = original_value;
				break;

			case strhash("log_path"):
				current_user_settings.log_directory = original_value;
				break;

			default:
				error_msg.emplace_back("unknow option: " + arg);
			}

		}
		catch (const std::exception &ex)
		{
			error_msg.emplace_back("invalid input: '" + arg + "'" + ", " + ex.what());
		}
	}

	check_settings(current_user_settings, error_msg);

	return current_user_settings;
}

void check_settings(user_settings &current_user_settings, std::vector<std::string> &error_msg)
{
	if (current_user_settings.destination_address.empty())
		error_msg.emplace_back("invalid destination_address setting");

	if (encryption_mode::empty != current_user_settings.encryption &&
		encryption_mode::unknow != current_user_settings.encryption &&
		encryption_mode::none != current_user_settings.encryption &&
		current_user_settings.encryption_password.empty())
		error_msg.emplace_back("encryption_password is not set");

	if (running_mode::empty == current_user_settings.mode)
		error_msg.emplace_back("running mode is not set");

	if (running_mode::client == current_user_settings.mode)
	{
		if (0 == current_user_settings.listen_port)
			error_msg.emplace_back("listen_port is not set");

		if (current_user_settings.listen_port_start > 0)
			error_msg.emplace_back("listen_port_start should not be set");

		if (current_user_settings.listen_port_end > 0)
			error_msg.emplace_back("listen_port_end should not be set");

		if (current_user_settings.destination_port == 0 &&
			(current_user_settings.destination_port_start == 0 ||
				current_user_settings.destination_port_end == 0))
		{
			error_msg.emplace_back("destination port setting incorrect");
		}
	}

	if (running_mode::server == current_user_settings.mode)
	{
		bool use_dynamic_ports = current_user_settings.listen_port_start || current_user_settings.listen_port_end;
		if (use_dynamic_ports)
		{
			if (0 == current_user_settings.listen_port_start)
				error_msg.emplace_back("listen_port_start is missing");

			if (0 == current_user_settings.listen_port_end)
				error_msg.emplace_back("listen_port_end is missing");

			if (current_user_settings.listen_port_start > 0 && current_user_settings.listen_port_end > 0)
			{
				if (current_user_settings.listen_port_end == current_user_settings.listen_port_start)
					error_msg.emplace_back("listen_port_start is equal to listen_port_end");

				if (current_user_settings.listen_port_end < current_user_settings.listen_port_start)
					error_msg.emplace_back("listen_port_end is less than listen_port_start");
			}
		}
		else
		{
			if (0 == current_user_settings.listen_port)
				error_msg.emplace_back("listen_port is not set");
		}

		if (0 == current_user_settings.destination_port)
			error_msg.emplace_back("destination_port is not set");

		if (current_user_settings.destination_port_start > 0)
			error_msg.emplace_back("destination_port_start should not be set");

		if (current_user_settings.destination_port_end > 0)
			error_msg.emplace_back("destination_port_end should not be set");
	}

	if (current_user_settings.timeout == 0)
		current_user_settings.timeout = DEFAULT_TIMEOUT;

	if (!current_user_settings.stun_server.empty())
	{
		if (0 == current_user_settings.listen_port)
			error_msg.emplace_back("do not specify multiple listen ports when STUN Server is set");
	}

	if (!current_user_settings.log_directory.empty())
	{
		if (std::filesystem::exists(current_user_settings.log_directory))
		{
			if (std::filesystem::is_directory(current_user_settings.log_directory))
			{
				current_user_settings.log_ip_address = current_user_settings.log_directory / "ip_address.log";
				current_user_settings.log_messages = current_user_settings.log_directory / "log_output.log";
			}
			else
				error_msg.emplace_back("Log Path is not directory");
		}
		else
		{
			error_msg.emplace_back("Log Path does not exist");
		}
	}
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
	output_file.open(log_file, std::ios::out | std::ios::app);
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
	output_file << message;
	output_file.close();
}
