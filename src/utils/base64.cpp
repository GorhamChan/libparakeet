#include "utils/base64.h"

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

namespace parakeet_crypto::utils
{

namespace base64_impl
{

constexpr static std::array<uint8_t, 64> b64_chr = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', //
                                                    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', //
                                                    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', //
                                                    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', //
                                                    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};

constexpr static auto b64_rchr = ([]() {
    std::array<uint8_t, 256> reverse_table{};
    for (size_t i = 0; i < reverse_table.size(); i++)
    {
        for (size_t j = 0; j < b64_chr.size(); j++)
        {
            if (b64_chr[j] == static_cast<uint8_t>(i))
            {
                reverse_table[i] = j;
                break;
            }
        }
    }

    return reverse_table;
})();

// NOLINTBEGIN(*-magic-numbers)
size_t b64_encode(uint8_t *output, const uint8_t *input, size_t input_len)
{
    auto *p_out = output;

    for (const auto *p_input_end = input + input_len - 3; input <= p_input_end;)
    {
        *p_out++ = b64_chr[input[0] >> 2];
        *p_out++ = b64_chr[((input[0] & 0b0000'0011) << 4) | (input[1] >> 4)];
        *p_out++ = b64_chr[((input[1] & 0b0000'1111) << 2) | (input[2] >> 6)];
        *p_out++ = b64_chr[((input[2] & 0b0011'1111))];

        input += 3;
    }

    input_len %= 3;
    if (input_len == 1)
    {
        *p_out++ = b64_chr[input[0] >> 2];
        *p_out++ = b64_chr[(input[0] & 0b0000'0011) << 4];
        *p_out++ = '=';
        *p_out++ = '=';
    }
    else if (input_len == 2)
    {
        *p_out++ = b64_chr[input[0] >> 2];
        *p_out++ = b64_chr[((input[0] & 0b0000'0011) << 4) | (input[1] >> 4)];
        *p_out++ = b64_chr[((input[1] & 0b0000'1111)) << 2];
        *p_out++ = '=';
    }

    *p_out = '\0';

    return p_out - output;
}

size_t b64_decode(uint8_t *output, const uint8_t *input, size_t input_len)
{
    auto *p_out = output;
    size_t total_decoded = 0;

    auto encode_block = [&p_out](const uint8_t *p_in) {
        // NOLINTBEGIN(*-identifier-length)
        uint8_t a{b64_rchr[p_in[0]]};
        uint8_t b{b64_rchr[p_in[1]]};
        uint8_t c{b64_rchr[p_in[2]]};
        uint8_t d{b64_rchr[p_in[3]]};
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
        if (encode_block(input))
        {
            return p_out - output;
        }
    }

    input_len %= 4;
    if (input_len != 0)
    {
        std::array<uint8_t, 4> buffer{0, '=', '=', '='};
        std::copy_n(input, input_len, buffer.begin());
        encode_block(buffer.data());
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
