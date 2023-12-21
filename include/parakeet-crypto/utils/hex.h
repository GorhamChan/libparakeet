#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace parakeet_crypto::utils
{

namespace detail
{

/**
 * Convert an integer type to hex string
 *
 * @param value The integer value
 * @param width The width, can be one of the following: [sizeof(u8), sizeof(u16), sizeof(u32), sizeof(u64)]
 * @param upper Should be upper case?
 * @return
 */
std::string IntToFixedWidthHexStringImpl(uint64_t value, size_t width, bool upper = false);
std::string IntToHexStringImpl(uint64_t value, bool upper = false);

}; // namespace detail

std::string Hex(const uint8_t *data, size_t len, bool upper = true);
std::vector<uint8_t> UnHex(const char *data);

template <typename T> std::string IntToHexString(T value, bool upper = false)
{
    if constexpr (sizeof(value) != sizeof(uint64_t))
    {
        // up cast without the negative bits
        auto value_u64 = static_cast<uint64_t>(value);
        auto mask = (uint64_t{1} << (sizeof(value) << 3)) - 1;
        return detail::IntToHexStringImpl(value_u64 & mask, upper);
    }

    return detail::IntToHexStringImpl(static_cast<uint64_t>(value), upper);
}

template <typename T> std::string IntToFixedWidthHexString(T value, bool upper = false)
{
    return detail::IntToFixedWidthHexStringImpl(static_cast<uint64_t>(value), sizeof(value), upper);
}

} // namespace parakeet_crypto::utils
