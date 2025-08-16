#pragma once
#include <algorithm>
#include <ranges>
#include <cctype>
#include <string>

namespace str_utils
{
	template<typename T>
	constexpr inline uint64_t strhash(const T* str, int h = 0)
	{
		return str[h] ? (strhash(str, h + 1) * 5) ^ static_cast<uint64_t>(str[h]) : 4096;
	}

	// trim from start (in place)
	inline void ltrim(std::string &s)
	{
		s.erase(s.begin(), std::ranges::find_if(s, [](auto ch) { return !isspace(ch); }));
	}

	// trim from end (in place)
	inline void rtrim(std::string &s)
	{
		s.erase(std::ranges::find_if(s | std::views::reverse, [](auto ch) { return !isspace(ch); }).base(), s.end());
	}

	// trim from both ends (in place)
	inline void trim(std::string &s)
	{
		rtrim(s);
		ltrim(s);
	}

	// trim from start (copying)
	inline std::string ltrim_copy(std::string_view s)
	{
		auto ltrim_view = s | std::views::drop_while(isspace);
		return std::string(ltrim_view.begin(), ltrim_view.end());
	}

	// trim from end (copying)
	inline std::string rtrim_copy(std::string_view s)
	{
		auto rtrim_view = s | std::views::reverse | std::views::drop_while(isspace) | std::views::reverse;
		return std::string(rtrim_view.begin(), rtrim_view.end());
	}

	// trim from both ends (copying)
	inline std::string trim_copy(std::string s)
	{
		auto trim_view = s | std::views::drop_while(isspace)
			| std::views::reverse
			| std::views::drop_while(isspace)
			| std::views::reverse;
		return std::string(trim_view.begin(), trim_view.end());
	}

	inline void to_lower(std::string &s)
	{
		std::ranges::transform(s, s.begin(), tolower);
	}

	inline std::string to_lower_copy(std::string_view s)
	{
		auto copy_view = s | std::views::transform(tolower);
		return std::string(copy_view.begin(), copy_view.end());
	}

	inline void to_upper(std::string &s)
	{
		std::ranges::transform(s, s.begin(), toupper);
	}

	inline std::string to_upper_copy(std::string_view s)
	{
		auto copy_view = s | std::views::transform(toupper);
		return std::string(copy_view.begin(), copy_view.end());
	}
}