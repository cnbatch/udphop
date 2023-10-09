#pragma once
#include "share_defines.hpp"

#ifndef _CONFIGURATIONS_HPP_
#define _CONFIGURATIONS_HPP_


user_settings parse_settings(const std::vector<std::string> &args, std::vector<std::string> &error_msg);
void check_settings(user_settings &current_user_settings, std::vector<std::string> &error_msg);


#endif
