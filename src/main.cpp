#include <algorithm>
#include <cmath>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <thread>

#include "shares/share_defines.hpp"
#include "shares/string_utils.hpp"
#include "networks/connections.hpp"
#include "modes/client.hpp"
#include "modes/server.hpp"
#include "modes/relay.hpp"

int main(int argc, char *argv[])
{
#ifdef __cpp_lib_format
	std::cout << std::format("{} version {}\n", app_name, app_version);
	if (argc <= 1)
	{
		std::cout << std::format("Usage: {} config1.conf\n", app_name);
		std::cout << std::format("       {} config1.conf config2.conf...\n", app_name);
		return 0;
	}
#else
	std::cout << app_name << " version " << app_version << "\n";
	if (argc <= 1)
	{
		std::cout << "Usage: " << app_name << " config1.conf\n";
		std::cout << "       " << app_name << " config1.conf config2.conf...\n";
		return 0;
	}
#endif

	unsigned pool_thread_count = std::thread::hardware_concurrency() + 1;
	task_thread_pool::task_thread_pool parallel_pool(pool_thread_count);

	asio::io_context network_io{1};
	asio::io_context task_context{1};
	
	std::vector<modes::client_mode> clients2;
	std::vector<modes::relay_mode> relays2;
	std::vector<modes::server_mode> servers2;
	std::vector<user_settings> profile_settings;

	bool error_found = false;
	bool check_config = false;

	for (int i = 1; i < argc; ++i)
	{
		if (str_utils::to_lower_copy(argv[i]) == "--check-config")
		{
			check_config = true;
			continue;
		}
		
		std::vector<std::string> lines;
		std::string line;
		std::ifstream input(argv[i]);
		while (std::getline(input, line))
		{
			lines.push_back(line);
		}

		std::vector<std::string> error_msg;
		user_settings current_settings = parse_from_args(lines, error_msg);
		std::filesystem::path config_input_name = argv[i];
		current_settings.config_filename = argv[i];
		if (!current_settings.log_directory.empty())
			current_settings.log_status = current_settings.log_directory / (config_input_name.filename().string() + "_status.log");
		profile_settings.emplace_back(std::move(current_settings));
		if (error_msg.size() > 0)
		{
#ifdef __cpp_lib_format
			std::cout << std::format("Error(s) found in setting file {}\n", argv[i]);
#else
			printf("Error(s) found in setting file %s\n", argv[i]);
#endif
			for (const std::string &each_one : error_msg)
			{
				std::cerr << "\t" << each_one << "\n";
			}
			std::cerr << std::endl;
			error_found = true;
			continue;
		}
	}

	std::cout << "Error Found in Configuration File(s): " << (error_found ? "Yes" : "No") << "\n";
	if (error_found || check_config)
		return 0;

	for (user_settings &settings : profile_settings)
	{
		switch (settings.mode)
		{
		case running_mode::client:
			clients2.emplace_back(modes::client_mode(network_io, task_context, parallel_pool, settings));
			break;
		case running_mode::relay:
			relays2.emplace_back(modes::relay_mode(network_io, task_context, parallel_pool, settings));
			break;
		case running_mode::server:
			servers2.emplace_back(modes::server_mode(network_io, task_context, parallel_pool, settings));
			break;
		default:
			break;
		}
	}

	std::cout << "Servers: " << servers2.size() << "\n";
	std::cout << "Relays: " << relays2.size() << "\n";
	std::cout << "Clients: " << clients2.size() << "\n";

	bool started_up = true;

	for (modes::server_mode &server : servers2)
	{
		started_up = server.start() && started_up;
	}

	for (modes::relay_mode &relay : relays2)
	{
		started_up = relay.start() && started_up;
	}

	for (modes::client_mode &client : clients2)
	{
		started_up = client.start() && started_up;
	}

	if (!error_found && started_up)
	{
		std::thread t([&]() { task_context.run(); });
		t.detach();
		network_io.run();
		task_context.stop();
	}

	return 0;
}