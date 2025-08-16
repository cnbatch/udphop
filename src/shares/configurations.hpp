#pragma once
#include <asio.hpp>
#include "share_defines.hpp"

#ifndef _CONFIGURATIONS_HPP_
#define _CONFIGURATIONS_HPP_


std::vector<std::string> parse_running_mode(const std::vector<std::string> &args, user_settings &current_user_settings);
std::vector<std::string> parse_the_rest(const std::vector<std::string> &args, user_settings &current_user_settings);
void check_settings(user_settings &current_user_settings, std::vector<std::string> &error_msg);
void copy_settings(user_settings &inner, user_settings &outter);
void verify_server_listen_port(user_settings &current_user_settings, std::vector<std::string> &error_msg);
void verify_client_destination(user_settings &current_user_settings, std::vector<std::string> &error_msg);


#endif
