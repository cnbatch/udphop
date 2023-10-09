#include <climits>
#include "configurations.hpp"
#include "string_utils.hpp"

user_settings parse_settings(const std::vector<std::string> &args, std::vector<std::string> &error_msg)
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
				if (auto time_interval = std::stoi(value); time_interval < constant_values::dport_refresh_minimal)
					current_user_settings.dynamic_port_refresh = constant_values::dport_refresh_minimal;
				else if (time_interval >= constant_values::dport_refresh_minimal && time_interval < USHRT_MAX)
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

			case strhash("ipv4_only"):
			{
				bool yes = value == "yes" || value == "true" || value == "1";
				current_user_settings.ipv4_only = yes;
				break;
			}

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
		current_user_settings.timeout = constant_values::default_timeout;

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

