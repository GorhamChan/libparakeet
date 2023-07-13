// Adapted from: https://github.com/Zunawe/md5-c/raw/f3529b666b7ae8b80b0a9fa88ac2a91b389909c7/md5.c
// License:      The Unlicense

/*
 * Derived from the RSA Data Security, Inc. MD5 Message-Digest Algorithm
 * and modified slightly to be functionally identical but condensed into control structures.
 */
#include "parakeet-crypto/utils/hash/md5.h"
#include "hash_helper.h"
#include "utils/endian_helper.h"

#include <array>
#include <cstring>

// NOLINTBEGIN(*-avoid-c-arrays,*-magic-numbers,*-identifier-length)

namespace parakeet_crypto::utils::hash
{

constexpr std::array<uint32_t, 64> kMD5Shifts = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                                                 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
                                                 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                                                 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

constexpr std::array<uint32_t, 64> kMD5Consts = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

void md5_transform(md5_ctx *ctx)
{
    uint32_t a{ctx->state[0]};
    uint32_t b{ctx->state[1]};
    uint32_t c{ctx->state[2]};
    uint32_t d{ctx->state[3]};

    auto get_m = [ctx](size_t i) { return ReadLittleEndian<uint32_t>(&ctx->buffer[(i % 16) * 4]); };

    auto FF = [&get_m](uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d, size_t i) {
        uint32_t f = (b & c) | (~b & d);
        size_t g = 1 * i + 0;
        f += a + kMD5Consts[i] + get_m(g);
        a = b + rol_u32(f, kMD5Shifts[i]);
    };

    auto GG = [&get_m](uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d, size_t i) {
        uint32_t f = (b & d) | (c & ~d);
        size_t g = 5 * i + 1;
        f += a + kMD5Consts[i] + get_m(g);
        a = b + rol_u32(f, kMD5Shifts[i]);
    };

    auto HH = [&get_m](uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d, size_t i) {
        uint32_t f = b ^ c ^ d;
        size_t g = 3 * i + 5;
        f += a + kMD5Consts[i] + get_m(g);
        a = b + rol_u32(f, kMD5Shifts[i]);
    };

    auto II = [&get_m](uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d, size_t i) {
        uint32_t f = c ^ (b | ~d);
        size_t g = 7 * i + 0;
        f += a + kMD5Consts[i] + get_m(g);
        a = b + rol_u32(f, kMD5Shifts[i]);
    };

    // 64 rounds, loop unrolled.
    FF(a, b, c, d, 0);
    FF(d, a, b, c, 1);
    FF(c, d, a, b, 2);
    FF(b, c, d, a, 3);
    FF(a, b, c, d, 4);
    FF(d, a, b, c, 5);
    FF(c, d, a, b, 6);
    FF(b, c, d, a, 7);
    FF(a, b, c, d, 8);
    FF(d, a, b, c, 9);
    FF(c, d, a, b, 10);
    FF(b, c, d, a, 11);
    FF(a, b, c, d, 12);
    FF(d, a, b, c, 13);
    FF(c, d, a, b, 14);
    FF(b, c, d, a, 15);

    GG(a, b, c, d, 16);
    GG(d, a, b, c, 17);
    GG(c, d, a, b, 18);
    GG(b, c, d, a, 19);
    GG(a, b, c, d, 20);
    GG(d, a, b, c, 21);
    GG(c, d, a, b, 22);
    GG(b, c, d, a, 23);
    GG(a, b, c, d, 24);
    GG(d, a, b, c, 25);
    GG(c, d, a, b, 26);
    GG(b, c, d, a, 27);
    GG(a, b, c, d, 28);
    GG(d, a, b, c, 29);
    GG(c, d, a, b, 30);
    GG(b, c, d, a, 31);

    HH(a, b, c, d, 32);
    HH(d, a, b, c, 33);
    HH(c, d, a, b, 34);
    HH(b, c, d, a, 35);
    HH(a, b, c, d, 36);
    HH(d, a, b, c, 37);
    HH(c, d, a, b, 38);
    HH(b, c, d, a, 39);
    HH(a, b, c, d, 40);
    HH(d, a, b, c, 41);
    HH(c, d, a, b, 42);
    HH(b, c, d, a, 43);
    HH(a, b, c, d, 44);
    HH(d, a, b, c, 45);
    HH(c, d, a, b, 46);
    HH(b, c, d, a, 47);

    II(a, b, c, d, 48);
    II(d, a, b, c, 49);
    II(c, d, a, b, 50);
    II(b, c, d, a, 51);
    II(a, b, c, d, 52);
    II(d, a, b, c, 53);
    II(c, d, a, b, 54);
    II(b, c, d, a, 55);
    II(a, b, c, d, 56);
    II(d, a, b, c, 57);
    II(c, d, a, b, 58);
    II(b, c, d, a, 59);
    II(a, b, c, d, 60);
    II(d, a, b, c, 61);
    II(c, d, a, b, 62);
    II(b, c, d, a, 63);

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
}

/*
 * Initialize a context
 */
void md5_init(md5_ctx *ctx)
{
    std::fill_n(&ctx->buffer[0], sizeof(ctx->buffer), 0);
    ctx->count = 0;

    /*
     * Constants defined by the MD5 algorithm
     */
    constexpr uint32_t A = 0x67452301;
    constexpr uint32_t B = 0xefcdab89;
    constexpr uint32_t C = 0x98badcfe;
    constexpr uint32_t D = 0x10325476;

    ctx->state[0] = A;
    ctx->state[1] = B;
    ctx->state[2] = C;
    ctx->state[3] = D;
}

/*
 * Add some amount of input to the context
 *
 * If the input fills out a block of 512 bits, apply the algorithm (md5Step)
 * and save the result in the buffer. Also updates the overall size.
 */
void md5_update(md5_ctx *ctx, const uint8_t *data, size_t len)
{
    size_t buffer_idx = ctx->count % 64;
    ctx->count += static_cast<uint64_t>(len);

    if ((buffer_idx + len) < 64)
    {
        memcpy(&ctx->buffer[buffer_idx], data, len);
        return;
    }

    const uint8_t *p_data = data;
    const uint8_t *p_end = p_data + len;
    const uint8_t *p_last_block = p_end - 64;

    // Use buffer first
    if (buffer_idx != 0)
    {
        size_t copy_n = 64 - buffer_idx;
        memcpy(&ctx->buffer[buffer_idx], p_data, copy_n);
        p_data += copy_n;

        md5_transform(ctx);
    }

    // Consume blocks from input buffer
    for (; p_data <= p_last_block; p_data += 64)
    {
        memcpy(&ctx->buffer[0], p_data, 64);
        md5_transform(ctx);
    }

    // Store left-over buffer
    size_t left_over = p_end - p_data;
    if (left_over > 0)
    {
        memcpy(&ctx->buffer[0], p_data, left_over);
    }
}

/*
 * Pad the current input to get to 448 bytes, append the size in bits to the very end,
 * and save the result of the final iteration into digest.
 */
void md5_final(md5_ctx *ctx, uint8_t *digest)
{
    auto [padding, padding_size] = prepare_md_final_block<kMD5BlockSize, false>(ctx->count);
    md5_update(ctx, padding.data(), padding_size);
    state_to_digest<false>(digest, &ctx->state[0], sizeof(ctx->state) / sizeof(ctx->state[0]));
}

} // namespace parakeet_crypto::utils::hash

// NOLINTEND(*-avoid-c-arrays,*-magic-numbers,*-identifier-length)
