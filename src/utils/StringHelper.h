#pragma once

#include <cstdint>

#include <algorithm>
#include <span>

namespace parakeet_crypto::utils {

template <typename... Args>
std::string Format(const char* fmt, Args... args) {
    auto text_len = std::snprintf(nullptr, 0, fmt, args...);
    if (text_len < 0) return "";

    // String contains the extra '\x00' at the end.
    std::string formatted(text_len, 0);
    std::snprintf(formatted.data(), text_len + 1, fmt, args...);
    return formatted;
}

inline std::vector<std::string> ParseCSVLine(std::span<const uint8_t> data) {
    std::vector<std::string> result;

    auto begin_next_str = data.begin();
    auto str_end = data.end();

    for (auto it = begin_next_str; it < str_end; it++) {
        if (*it == ',') {
            result.push_back(std::string(begin_next_str, it));
            begin_next_str = it + 1;
        }
    }

    if (begin_next_str != str_end) {
        result.push_back(std::string(begin_next_str, str_end));
    }

    return result;
}

}  // namespace parakeet_crypto::utils
