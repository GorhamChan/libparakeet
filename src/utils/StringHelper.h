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

    auto p_next_str = data.begin();
    for (auto p = p_next_str; p < data.end(); p++) {
        if (*p == ',') {
            result.push_back(std::string(p_next_str, p));
            p_next_str = p + 1;
        }
    }

    if (p_next_str != data.end()) {
        result.push_back(std::string(p_next_str, data.end()));
    }

    return result;
}

}  // namespace parakeet_crypto::utils
