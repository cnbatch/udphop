﻿#include <algorithm>
#include <cmath>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <thread>

#include "shares/share_defines.hpp"
#include "shares/string_utils.hpp"
#include "networks/connections.hpp"
#include "networks/client.hpp"
#include "networks/server.hpp"
#include "networks/relay.hpp"

int main(int argc, char *argv[])
{
#ifdef __cpp_lib_format
	std::cout << std::format("{} version {}\n", app_name, app_version);
	if (argc <= 1)
	{
		std::cout << std::format("Usage: {} config1.conf\n", app_name);
		std::cout << std::format("       {} config1.conf config2.conf...\n", (int)app_name.length(), app_name.data());
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

	//uint16_t thread_group_count = 2;
	//int io_thread_count = std::thread::hardware_concurrency() == 1 ? 1 : 2;
	//std::unique_ptr<ttp::task_thread_pool> parallel_pool_1;
	//std::unique_ptr<ttp::task_thread_pool> parallel_pool_2;
	//if (std::thread::hardware_concurrency() > 2)
	//{
	//	auto thread_counts = std::thread::hardware_concurrency();
	//	thread_group_count = thread_counts;
	//	io_thread_count = (int)round(log2(thread_counts));
	//}

	//if (std::thread::hardware_concurrency() > 1)
	//{
	//	parallel_pool_1 = std::make_unique<ttp::task_thread_pool>();
	//	parallel_pool_2 = std::make_unique<ttp::task_thread_pool>();
	//}

	//ttp::task_group_pool task_groups{ thread_group_count };
	//task_pool_colloector task_pools =
	//{
	//	.parallel_encryption_pool = parallel_pool_1.get(),
	//	.parallel_decryption_pool = parallel_pool_2.get(),
	//	.listener_parallels = parallel_pool_1.get(),
	//	.forwarder_parallels = parallel_pool_2.get()
	//};

	//asio::io_context ioc{ io_thread_count };
	asio::io_context ioc;

	std::vector<client_mode> clients;
	std::vector<relay_mode> relays;
	std::vector<server_mode> servers;
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
		std::ifstream input(argv[i]);
		std::copy(
			std::istream_iterator<std::string>(input),
			std::istream_iterator<std::string>(),
			std::back_inserter(lines));

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
			clients.emplace_back(client_mode(ioc, /*task_groups, task_pools,*/ settings));
			break;
		case running_mode::relay:
			relays.emplace_back(relay_mode(ioc, /*task_groups, task_pools,*/ settings));
			break;
		case running_mode::server:
			servers.emplace_back(server_mode(ioc, /*task_groups, task_pools,*/ settings));
			break;
		default:
			break;
		}
	}

	std::cout << "Servers: " << servers.size() << "\n";
	std::cout << "Relays: " << relays.size() << "\n";
	std::cout << "Clients: " << clients.size() << "\n";

	bool started_up = true;

	for (server_mode &server : servers)
	{
		started_up = server.start() && started_up;
	}
	
	for (relay_mode &relay : relays)
	{
		started_up = relay.start() && started_up;
	}

	for (client_mode &client : clients)
	{
		started_up = client.start() && started_up;
	}

	if (!error_found && started_up)
	{
		ioc.run();
	}

	return 0;
}