#include "parakeet-crypto/utils/hex.h"

#include <cstddef>
#include <cstdint>
#include <string>

namespace parakeet_crypto::utils
{

constexpr const char *kHexUpper = "0123456789ABCDEF";
constexpr const char *kHexLower = "0123456789abcdef";

constexpr size_t kShiftUpperHalfByte = 4;
constexpr size_t kMaskLowerHalfByte = 0x0F;

std::string Hex(const uint8_t *data, size_t len, bool upper)
{
    const char *hex_table = upper ? kHexUpper : kHexLower;
    std::string result(len * 2, 0);

    size_t write_offset = 0;
    for (size_t i = 0; i < len; i++)
    {
        auto value = data[i];
        result[write_offset++] = hex_table[value >> kShiftUpperHalfByte];
        result[write_offset++] = hex_table[value & kMaskLowerHalfByte];
    }

    return result;
}

constexpr uint8_t kUnHexFail = 0xff;
inline uint8_t UnHexChar(char chr)
{
    // '0': 00110000
    // '9': 00111001
    if (chr >= '0' && chr <= '9')
    {
        return chr - '0';
    }

    // NOLINTBEGIN(*-magic-numbers)
    // 'A': 0100_0001
    // 'F': 0100_0110
    // 'a': 0110_0001
    // 'f': 0110_0110
    if ((chr & 0b1101'1000) == 0b0100'0000)
    {
        chr &= 0b111;
        if (chr >= 0b001 && chr <= 0b110)
        {
            return chr - 1 + 0x0A;
        }
    }
    return kUnHexFail;
    // NOLINTEND(*-magic-numbers)
}

std::vector<uint8_t> UnHex(const char *data)
{
    std::vector<uint8_t> result;

    bool is_high = true;
    uint8_t next_byte = 0;

    char chr{};
    while ((chr = *data++) != 0)
    {
        auto decoded = UnHexChar(chr);
        if (decoded == kUnHexFail)
        {
            is_high = true;
            continue;
        }
        next_byte = (next_byte << 4) | decoded;

        if (is_high)
        {
            // handle high-byte
            is_high = false;
        }
        else
        {
            // handle lo-byte
            is_high = true;
            result.push_back(next_byte);
        }
    }

    return result;
}

constexpr size_t kU64Bits = sizeof(uint64_t) * 8;

std::string detail::IntToFixedWidthHexStringImpl(uint64_t value, size_t width, bool upper)
{
    if (width < sizeof(uint8_t) || width > sizeof(uint64_t))
    {
        return "";
    }

    size_t char_count = width * 2;
    std::string result(char_count, '0');

    value &= UINT64_MAX >> (kU64Bits - (width << 3));
    const char *hex_table = upper ? kHexUpper : kHexLower;

    for (size_t i = char_count - 1; value != 0;)
    {
        result[i--] = hex_table[value & kMaskLowerHalfByte];
        value >>= kShiftUpperHalfByte;

        result[i--] = hex_table[value & kMaskLowerHalfByte];
        value >>= kShiftUpperHalfByte;
    }

    return result;
}

std::string detail::IntToHexStringImpl(uint64_t value, bool upper)
{
    constexpr size_t kInitShift = kU64Bits - 4;
    constexpr size_t kCheckMask = 0x0F;

    if (value == 0)
    {
        return "0";
    }

    const char *hex_table = upper ? kHexUpper : kHexLower;

    int shifts = kInitShift;
    while (((value >> shifts) & kCheckMask) == 0)
    {
        shifts -= 4;
    }

    std::string result;
    while (shifts >= 0)
    {
        result += hex_table[(value >> shifts) & kMaskLowerHalfByte];
        shifts -= 4;
    }
    return result;
}

} // namespace parakeet_crypto::utils
