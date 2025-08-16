#pragma once

#include <string>
#include <asio.hpp>

#ifndef _DNS_HELPER_HPP_
#define _DNS_HELPER_HPP_

namespace dns_helper
{
	void save_ddns_result(const std::string &exe_path, asio::ip::address input_address, asio::ip::port_type port_number);

	std::pair<asio::ip::address, asio::ip::port_type> query_dns_txt(const std::string &fqdn, std::vector<std::string> &error_msg);
}
#endif