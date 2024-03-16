#include <climits>
#include "configurations.hpp"
#include "string_utils.hpp"

using namespace str_utils;

std::vector<std::string> parse_running_mode(const std::vector<std::string> &args, user_settings &current_user_settings)
{
	std::vector<std::string> error_messages;
	uint16_t count = 0;

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
			{
				switch (strhash(value.c_str()))
				{
				case strhash("server"):
					current_user_settings.mode = running_mode::server;
					break;
				case strhash("client"):
					current_user_settings.mode = running_mode::client;
					break;
				case strhash("relay"):
					current_user_settings.mode = running_mode::relay;
					break;
				default:
					current_user_settings.mode = running_mode::unknow;
					error_messages.emplace_back("invalid mode: " + value);
					break;
				}
				count++;
				break;
			}
			default:
				break;
			}
		}
		catch (const std::exception &ex)
		{
			error_messages.emplace_back("invalid input: '" + arg + "'" + ", " + ex.what());
		}
	}

	if (count == 0)
		error_messages.emplace_back("running mode is not set");

	if (count > 1)
		error_messages.emplace_back("Too many 'mode=' in configuration file.");

	return error_messages;
}

std::vector<std::string> parse_the_rest(const std::vector<std::string> &args, user_settings &current_user_settings)
{
	std::vector<std::string> error_msg;
	user_settings *current_settings = &current_user_settings;

	for (const std::string &arg : args)
	{
		auto line = trim_copy(arg);
		if (line.empty() || line[0] == '#')
			continue;
		auto eq = line.find_first_of("=");
		std::string name = line.substr(0, eq);
		std::string value = line.substr(eq + 1);
		trim(name);
		trim(value);
		std::string original_value = value;
		to_lower(name);
		to_lower(value);
		if (eq == std::string::npos)
		{
			if (line.front() != '[' || line.back() != ']')
			{
				error_msg.emplace_back("unknow option: " + arg);
				continue;
			}
		}
		else
		{
			value = line.substr(eq + 1);
			trim(value);
			original_value = value;
			to_lower(value);

			if (value.empty())
				continue;
		}

		try
		{
			switch (strhash(name.c_str()))
			{
			case strhash("mode"):
				break;

			case strhash("listen_on"):
				current_settings->listen_on = original_value;
				break;

			case strhash("listen_port"):
				if (auto pos = value.find("-"); pos == std::string::npos)
				{
					if (auto port_number = std::stoi(value); port_number > 0 && port_number < USHRT_MAX)
						current_settings->listen_port = static_cast<uint16_t>(port_number);
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
						current_settings->listen_port_start = static_cast<uint16_t>(port_number);
					else
						error_msg.emplace_back("invalid listen_port_start number: " + start_port);

					if (auto port_number = std::stoi(end_port); port_number > 0 && port_number < USHRT_MAX)
						current_settings->listen_port_end = static_cast<uint16_t>(port_number);
					else
						error_msg.emplace_back("invalid listen_port_end number: " + end_port);
				}
				break;

			case strhash("dport_refresh"):	// client only
				if (auto time_interval = std::stoi(value); time_interval < constant_values::dport_refresh_minimal)
					current_settings->dynamic_port_refresh = constant_values::dport_refresh_minimal;
				else if (time_interval >= constant_values::dport_refresh_minimal && time_interval < USHRT_MAX)
					current_settings->dynamic_port_refresh = static_cast<uint16_t>(time_interval);
				else
					current_settings->dynamic_port_refresh = USHRT_MAX;
				break;

			case strhash("destination_port"):
				if (auto pos = value.find("-"); pos == std::string::npos)
				{
					if (auto port_number = std::stoi(value); port_number > 0 && port_number < 65536)
						current_settings->destination_port = static_cast<uint16_t>(port_number);
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
						current_settings->destination_port_start = static_cast<uint16_t>(port_number);
					else
						error_msg.emplace_back("invalid destination_port_start number: " + start_port);

					if (auto port_number = std::stoi(end_port); port_number > 0 && port_number < USHRT_MAX)
						current_settings->destination_port_end = static_cast<uint16_t>(port_number);
					else
						error_msg.emplace_back("invalid destination_port_end number: " + end_port);
				}
				break;


			case strhash("destination_address"):
				current_settings->destination_address = value;
				break;

			case strhash("encryption_password"):
				current_settings->encryption_password = original_value;
				break;

			case strhash("encryption_algorithm"):
				switch (strhash(value.c_str()))
				{
				case strhash("none"):
					current_settings->encryption = encryption_mode::none;
					break;
				case strhash("aes-gcm"):
					current_settings->encryption = encryption_mode::aes_gcm;
					break;
				case strhash("aes-ocb"):
					current_settings->encryption = encryption_mode::aes_ocb;
					break;
				case strhash("chacha20"):
					current_settings->encryption = encryption_mode::chacha20;
					break;
				case strhash("xchacha20"):
					current_settings->encryption = encryption_mode::xchacha20;
					break;
				default:
					current_settings->encryption = encryption_mode::unknow;
					error_msg.emplace_back("encryption_algorithm is incorrect: " + value);
					break;
				}
				break;

			case strhash("timeout"):
				if (auto time_interval = std::stoi(value); time_interval <= 0 || time_interval > USHRT_MAX)
					current_settings->timeout = 0;
				else
					current_settings->timeout = static_cast<uint16_t>(time_interval);
				break;

			case strhash("keep_alive"):
				if (auto time_interval = std::stoi(value); time_interval <= 0)
					current_settings->keep_alive = 0;
				else if (time_interval > 0 && time_interval < USHRT_MAX)
					current_settings->keep_alive = static_cast<uint16_t>(time_interval);
				else
					current_settings->keep_alive = USHRT_MAX;
				break;

			case strhash("stun_server"):
				current_settings->stun_server = original_value;
				break;

			case strhash("log_path"):
				current_settings->log_directory = original_value;
				break;

			case strhash("ipv4_only"):
			{
				bool yes = value == "yes" || value == "true" || value == "1";
				current_settings->ip_version_only |= ip_only_options::ipv4;
				break;
			}

			case strhash("ipv6_only"):
			{
				bool yes = value == "yes" || value == "true" || value == "1";
				current_settings->ip_version_only = ip_only_options::ipv6;
				break;
			}

			case strhash("fec"):
				if (auto pos = value.find(":"); pos == std::string::npos)
				{
					error_msg.emplace_back("invalid fec format: " + value);
				}
				else
				{
					std::string fec_data_part = value.substr(0, pos);
					std::string fec_redundant_part = value.substr(pos + 1);
					trim(fec_data_part);
					trim(fec_redundant_part);

					if (fec_data_part.empty() || fec_redundant_part.empty())
					{
						error_msg.emplace_back("invalid fec setting: " + value);
						break;
					}

					int fec_data_number = std::stoi(fec_data_part);
					int fec_redundant_number = std::stoi(fec_redundant_part);

					if (fec_data_number > 0 && fec_data_number <= UCHAR_MAX)
						current_settings->fec_data = static_cast<uint8_t>(fec_data_number);

					if (fec_redundant_number > 0 && fec_redundant_number <= UCHAR_MAX)
						current_settings->fec_redundant = static_cast<uint8_t>(fec_redundant_number);

					if (int sum = fec_data_number + fec_redundant_number; sum > UCHAR_MAX)
						error_msg.emplace_back("the sum of fec value is too large: " + std::to_string(sum) + " (" + arg + ")");

					if (current_settings->fec_data == 0 || current_settings->fec_redundant == 0)
						current_settings->fec_data = current_settings->fec_redundant = 0;
				}
				break;

			case strhash("[listener]"):
			{
				if (current_user_settings.mode == running_mode::relay)
				{
					if (current_user_settings.ingress == nullptr)
					{
						current_user_settings.ingress = std::make_shared<user_settings>();
						current_user_settings.ingress->mode = running_mode::relay_ingress;
					}
					current_settings = current_user_settings.ingress.get();
				}
				else
				{
					error_msg.emplace_back("invalid section tag: " + arg);
				}
				break;
			}

			case strhash("[forwarder]"):
			{
				if (current_user_settings.mode == running_mode::relay)
				{
					if (current_user_settings.egress == nullptr)
					{
						current_user_settings.egress = std::make_shared<user_settings>();
						current_user_settings.egress->mode = running_mode::relay_egress;
					}
					current_settings = current_user_settings.egress.get();
				}
				else
				{
					error_msg.emplace_back("invalid section tag: " + arg);
				}
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

	return error_msg;
}

void check_settings(user_settings &current_user_settings, std::vector<std::string> &error_msg)
{
	if (current_user_settings.mode == running_mode::relay)
	{
		if (current_user_settings.ingress == nullptr && current_user_settings.egress == nullptr)
		{
			error_msg.emplace_back("[listener] and [forwarder] are missing");
		}

		if (current_user_settings.ingress != nullptr || current_user_settings.egress != nullptr)
		{
			if (current_user_settings.ingress == nullptr)
				error_msg.emplace_back("[listener] is missing");

			if (current_user_settings.egress == nullptr)
				error_msg.emplace_back("[forwarder] is missing");
		}
	}

	if (current_user_settings.ingress != nullptr)
		copy_settings(*current_user_settings.ingress, current_user_settings);

	if (current_user_settings.egress != nullptr)
		copy_settings(*current_user_settings.egress, current_user_settings);

	if ((current_user_settings.mode == running_mode::server || current_user_settings.mode == running_mode::client) &&
		current_user_settings.destination_address.empty())
		error_msg.emplace_back("invalid destination_address setting");

	if (current_user_settings.encryption != encryption_mode::empty &&
		current_user_settings.encryption != encryption_mode::unknow &&
		current_user_settings.encryption != encryption_mode::none &&
		current_user_settings.encryption_password.empty())
		error_msg.emplace_back("encryption_password is not set");

	if (current_user_settings.mode == running_mode::empty)
		error_msg.emplace_back("running mode is not set");

	if (current_user_settings.mode == running_mode::client)
	{
		if (current_user_settings.listen_port == 0)
			error_msg.emplace_back("listen_port is not set");

		if (current_user_settings.listen_port_start > 0)
			error_msg.emplace_back("listen_port_start should not be set");

		if (current_user_settings.listen_port_end > 0)
			error_msg.emplace_back("listen_port_end should not be set");

		verify_client_destination(current_user_settings, error_msg);
	}

	if (current_user_settings.mode == running_mode::server)
	{
		verify_server_listen_port(current_user_settings, error_msg);

		if (current_user_settings.destination_port == 0)
			error_msg.emplace_back("destination_port is not set");

		if (current_user_settings.destination_port_start > 0)
			error_msg.emplace_back("destination_port_start should not be set");

		if (current_user_settings.destination_port_end > 0)
			error_msg.emplace_back("destination_port_end should not be set");
	}

	if (current_user_settings.mode == running_mode::relay_ingress)
		verify_server_listen_port(current_user_settings, error_msg);

	if (current_user_settings.mode == running_mode::relay_egress)
		verify_client_destination(current_user_settings, error_msg);

	if (current_user_settings.timeout == 0)
		current_user_settings.timeout = constant_values::default_timeout;

	if (!current_user_settings.stun_server.empty() && current_user_settings.mode != running_mode::relay)
	{
		if (current_user_settings.listen_port == 0)
			error_msg.emplace_back("do not specify multiple listen ports when STUN Server is set");
	}

	if (!current_user_settings.log_directory.empty() &&
		current_user_settings.mode != running_mode::relay_ingress &&
		current_user_settings.mode != running_mode::relay_egress)
	{
		if (std::filesystem::exists(current_user_settings.log_directory))
		{
			if (std::filesystem::is_directory(current_user_settings.log_directory))
			{
				std::string filename;
				switch (current_user_settings.mode)
				{
				case running_mode::client:
					filename = "client_output.log";
					break;
				case running_mode::server:
					filename = "server_output.log";
					break;
				case running_mode::relay:
					filename = "relay_output.log";
					break;
				default:
					filename = "log_output.log";
					break;
				}
				current_user_settings.log_ip_address = current_user_settings.log_directory / "ip_address.log";
				current_user_settings.log_messages = current_user_settings.log_directory / filename;
			}
			else
				error_msg.emplace_back("Log Path is not directory");
		}
		else
		{
			error_msg.emplace_back("Log Path does not exist");
		}
	}

	if (current_user_settings.ip_version_only == (ip_only_options::ipv4 | ip_only_options::ipv6))
		error_msg.emplace_back("Both ipv4_only and ipv6_only are set as true");

	if (error_msg.empty() && current_user_settings.ingress != nullptr)
		check_settings(*current_user_settings.ingress, error_msg);

	if (error_msg.empty() && current_user_settings.egress != nullptr)
		check_settings(*current_user_settings.egress, error_msg);
}

void copy_settings(user_settings &inner, user_settings &outter)
{
	if (outter.fec_data > 0)
		inner.fec_data = outter.fec_data;

	if (outter.fec_redundant > 0)
		inner.fec_redundant = outter.fec_redundant;

	if (outter.encryption != encryption_mode::unknow &&
		outter.encryption != encryption_mode::empty &&
		outter.encryption != encryption_mode::none)
		inner.encryption = outter.encryption;

	if (!outter.encryption_password.empty())
		inner.encryption_password = outter.encryption_password;

	if (outter.timeout > 0)
		inner.timeout = outter.timeout;

	if (outter.keep_alive > 0)
		inner.keep_alive = outter.keep_alive;

	if (outter.ip_version_only != ip_only_options::not_set)
		inner.ip_version_only = outter.ip_version_only;
}

void verify_server_listen_port(user_settings &current_user_settings, std::vector<std::string>& error_msg)
{
	bool use_dynamic_ports = current_user_settings.listen_port_start || current_user_settings.listen_port_end;
	if (use_dynamic_ports)
	{
		if (current_user_settings.listen_port_start == 0)
			error_msg.emplace_back("listen_port_start is missing");

		if (current_user_settings.listen_port_end == 0)
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
		if (current_user_settings.listen_port == 0)
			error_msg.emplace_back("listen_port is not set");
	}
}

void verify_client_destination(user_settings &current_user_settings, std::vector<std::string>& error_msg)
{
	if (current_user_settings.destination_port == 0 &&
		(current_user_settings.destination_port_start == 0 ||
			current_user_settings.destination_port_end == 0))
	{
		error_msg.emplace_back("destination port setting incorrect");
	}
}

