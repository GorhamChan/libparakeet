#include "parakeet-crypto/utils/base64.h"

// Adapted from: https://raw.githubusercontent.com/joedf/base64.c/7896e2862488a85fef8452cc1b42c7cb8e707888/base64.c
// License:      MIT License
/*
    base64.c - by Joe DF (joedf@ahkscript.org)
    Released under the MIT License

    See "base64.h", for more information.

    Thank you for inspiration:
    http://www.codeproject.com/Tips/813146/Fast-base-functions-for-encode-decode
*/

#include <algorithm>
#include <array>

namespace parakeet_crypto::utils
{

namespace base64_impl
{

constexpr static auto kBase64Table = ([]() {
    const char *table_str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                            "abcdefghijklmnopqrstuvwxyz"
                            "0123456789"
                            "+/";
    std::array<uint8_t, 64> table{};
    for (auto &item : table)
    {
        item = *table_str++;
    }
    return table;
})();

template <typename T>
inline constexpr int IndexOf(const T &container, typename T::value_type needle, typename T::value_type fallback = 0)
{
    for (size_t i = 0; i < container.size(); i++)
    {
        if (container[i] == needle)
        {
            return static_cast<int>(i);
        }
    }
    return fallback;
}

constexpr static auto kBase64ReverseTable = ([]() {
    std::array<uint8_t, 256> reverse_table{};

    for (size_t i = 0; i < reverse_table.size(); i++)
    {
        reverse_table[i] = IndexOf(kBase64Table, static_cast<uint8_t>(i));
    }

    return reverse_table;
})();

// NOLINTBEGIN(*-magic-numbers)
size_t b64_encode(uint8_t *output, const uint8_t *input, size_t input_len)
{
    auto *p_out = output;

    for (const auto *p_input_end = input + input_len - 3; input <= p_input_end;)
    {
        *p_out++ = kBase64Table[input[0] >> 2];
        *p_out++ = kBase64Table[((input[0] & 0b0000'0011) << 4) | (input[1] >> 4)];
        *p_out++ = kBase64Table[((input[1] & 0b0000'1111) << 2) | (input[2] >> 6)];
        *p_out++ = kBase64Table[((input[2] & 0b0011'1111))];

        input += 3;
    }

    input_len %= 3;
    if (input_len == 1)
    {
        *p_out++ = kBase64Table[input[0] >> 2];
        *p_out++ = kBase64Table[(input[0] & 0b0000'0011) << 4];
        *p_out++ = '=';
        *p_out++ = '=';
    }
    else if (input_len == 2)
    {
        *p_out++ = kBase64Table[input[0] >> 2];
        *p_out++ = kBase64Table[((input[0] & 0b0000'0011) << 4) | (input[1] >> 4)];
        *p_out++ = kBase64Table[((input[1] & 0b0000'1111)) << 2];
        *p_out++ = '=';
    }

    *p_out = '\0';

    return p_out - output;
}

size_t b64_decode(uint8_t *output, const uint8_t *input, size_t input_len)
{
    auto *p_out = output;
    size_t total_decoded = 0;

    auto decode_block = [&p_out](const uint8_t *p_in) {
        // NOLINTBEGIN(*-identifier-length)
        uint8_t a{kBase64ReverseTable[p_in[0]]};
        uint8_t b{kBase64ReverseTable[p_in[1]]};
        uint8_t c{kBase64ReverseTable[p_in[2]]};
        uint8_t d{kBase64ReverseTable[p_in[3]]};
        // NOLINTEND(*-identifier-length)

        *p_out++ = (a << 2) | (b >> 4);
        *p_out++ = (b << 4) | (c >> 2);
        *p_out++ = (c << 6) | (d >> 0);

        if (p_in[2] == '=')
        {
            p_out -= 2;
            return true;
        }

        if (p_in[3] == '=')
        {
            p_out -= 1;
            return true;
        }

        return false;
    };

    for (const auto *p_input_end = input + input_len - 4; input <= p_input_end; input += 4)
    {
        if (decode_block(input))
        {
            return p_out - output;
        }
    }

    input_len %= 4;
    if (input_len != 0)
    {
        std::array<uint8_t, 4> buffer{0, '=', '=', '='};
        std::copy_n(input, input_len, buffer.begin());
        decode_block(buffer.data());
    }
    return p_out - output;
}
// NOLINTEND(*-magic-numbers)

} // namespace base64_impl

std::vector<uint8_t> Base64Encode(const uint8_t *input, size_t len)
{
    std::vector<uint8_t> result(base64_impl::b64_encode_buffer_len(len));
    result.resize(base64_impl::b64_encode(result.data(), input, len));
    return result;
}

std::vector<uint8_t> Base64Decode(const uint8_t *input, size_t len)
{
    std::vector<uint8_t> result(base64_impl::b64_decode_buffer_len(len));
    result.resize(base64_impl::b64_decode(result.data(), input, len));
    return result;
}

} // namespace parakeet_crypto::utils
