// Adapted from: https://github.com/clibs/sha1/raw/d9ae30f34095107ece9dceb224839f0dc2f9c1c7/sha1.c
// License:      Public Domain

/*
    SHA-1 in C
    By Steve Reid <steve@edmweb.com>
    100% Public Domain

    Test Vectors (from FIPS PUB 180-1)
    "abc"
        A9993E36 4706816A BA3E2571 7850C26C 9CD0D89D
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        84983E44 1C3BD26E BAAE4AA1 F95129E5 E54670F1
    A million repetitions of "a"
        34AA973C D4C4DAA4 F61EEB2B DBAD2731 6534016F
*/

#include <algorithm>
#include <cstdio>
#include <cstring>

#include "parakeet-crypto/utils/hash/sha1.h"

#include "hash_helper.h"
#include "utils/endian_helper.h"

// NOLINTBEGIN(*-avoid-c-arrays,*-magic-numbers,*-identifier-length)

namespace parakeet_crypto::utils::hash
{

// constants
constexpr uint32_t kSHA1Const1 = 0x5A827999;
constexpr uint32_t kSHA1Const2 = 0x6ED9EBA1;
constexpr uint32_t kSHA1Const3 = 0x8f1bbcdc;
constexpr uint32_t kSHA1Const4 = 0xca62c1d6;

/* Hash a single 512-bit block. This is the core of the algorithm. */
inline void sha1_transform(sha1_ctx *ctx)
{
    typedef union {
        uint8_t c[64];
        uint32_t l[16];
    } CHAR64LONG16;

    auto *block = reinterpret_cast<CHAR64LONG16 *>(&ctx->buffer[0]); // NOLINT(*-reinterpret-cast)
    auto *block_l = &block->l[0];

    /* Copy ctx->state[] to working vars */
    uint32_t a{ctx->state[0]};
    uint32_t b{ctx->state[1]};
    uint32_t c{ctx->state[2]};
    uint32_t d{ctx->state[3]};
    uint32_t e{ctx->state[4]};

    auto get_w = [&block_l](uint32_t i) {
        if (i < 16)
        {
            block_l[i] = SwapHostToBigEndian(block_l[i]);
            return block_l[i];
        }

        // w[i] = (w[i-3] xor w[i-8] xor w[i-14] xor w[i-16]) leftrotate 1
        auto w_3 = block_l[(i + 13) % 16];
        auto w_8 = block_l[(i + 8) % 16];
        auto w_14 = block_l[(i + 2) % 16];
        auto &w_16 = block_l[(i + 0) % 16];

        w_16 = rol_u32(w_3 ^ w_8 ^ w_14 ^ w_16, 1);
        return w_16;
    };

    // R1, R2, R3, R4 are the different operations used in SHA1
    auto R1 = [&get_w](uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d, uint32_t &e, uint32_t i) -> void {
        uint32_t f = (b & (c ^ d)) ^ d;
        e += rol_u32(a, 5) + f + kSHA1Const1 + get_w(i);
        b = rol_u32(b, 30);
    };

    auto R2 = [&get_w](uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d, uint32_t &e, uint32_t i) -> void {
        uint32_t f = b ^ c ^ d;
        e += rol_u32(a, 5) + f + kSHA1Const2 + get_w(i);
        b = rol_u32(b, 30);
    };

    auto R3 = [&get_w](uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d, uint32_t &e, uint32_t i) -> void {
        uint32_t f = ((b | c) & d) | (b & c);
        e += rol_u32(a, 5) + f + kSHA1Const3 + get_w(i);
        b = rol_u32(b, 30);
    };

    auto R4 = [&get_w](uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d, uint32_t &e, uint32_t i) -> void {
        uint32_t f = b ^ c ^ d;
        e += rol_u32(a, 5) + f + kSHA1Const4 + get_w(i);
        b = rol_u32(b, 30);
    };

    // 4 rounds of 20 operations each. Loop unrolled.
    R1(a, b, c, d, e, 0);
    R1(e, a, b, c, d, 1);
    R1(d, e, a, b, c, 2);
    R1(c, d, e, a, b, 3);
    R1(b, c, d, e, a, 4);
    R1(a, b, c, d, e, 5);
    R1(e, a, b, c, d, 6);
    R1(d, e, a, b, c, 7);
    R1(c, d, e, a, b, 8);
    R1(b, c, d, e, a, 9);
    R1(a, b, c, d, e, 10);
    R1(e, a, b, c, d, 11);
    R1(d, e, a, b, c, 12);
    R1(c, d, e, a, b, 13);
    R1(b, c, d, e, a, 14);
    R1(a, b, c, d, e, 15);
    R1(e, a, b, c, d, 16);
    R1(d, e, a, b, c, 17);
    R1(c, d, e, a, b, 18);
    R1(b, c, d, e, a, 19);

    R2(a, b, c, d, e, 20);
    R2(e, a, b, c, d, 21);
    R2(d, e, a, b, c, 22);
    R2(c, d, e, a, b, 23);
    R2(b, c, d, e, a, 24);
    R2(a, b, c, d, e, 25);
    R2(e, a, b, c, d, 26);
    R2(d, e, a, b, c, 27);
    R2(c, d, e, a, b, 28);
    R2(b, c, d, e, a, 29);
    R2(a, b, c, d, e, 30);
    R2(e, a, b, c, d, 31);
    R2(d, e, a, b, c, 32);
    R2(c, d, e, a, b, 33);
    R2(b, c, d, e, a, 34);
    R2(a, b, c, d, e, 35);
    R2(e, a, b, c, d, 36);
    R2(d, e, a, b, c, 37);
    R2(c, d, e, a, b, 38);
    R2(b, c, d, e, a, 39);

    R3(a, b, c, d, e, 40);
    R3(e, a, b, c, d, 41);
    R3(d, e, a, b, c, 42);
    R3(c, d, e, a, b, 43);
    R3(b, c, d, e, a, 44);
    R3(a, b, c, d, e, 45);
    R3(e, a, b, c, d, 46);
    R3(d, e, a, b, c, 47);
    R3(c, d, e, a, b, 48);
    R3(b, c, d, e, a, 49);
    R3(a, b, c, d, e, 50);
    R3(e, a, b, c, d, 51);
    R3(d, e, a, b, c, 52);
    R3(c, d, e, a, b, 53);
    R3(b, c, d, e, a, 54);
    R3(a, b, c, d, e, 55);
    R3(e, a, b, c, d, 56);
    R3(d, e, a, b, c, 57);
    R3(c, d, e, a, b, 58);
    R3(b, c, d, e, a, 59);

    R4(a, b, c, d, e, 60);
    R4(e, a, b, c, d, 61);
    R4(d, e, a, b, c, 62);
    R4(c, d, e, a, b, 63);
    R4(b, c, d, e, a, 64);
    R4(a, b, c, d, e, 65);
    R4(e, a, b, c, d, 66);
    R4(d, e, a, b, c, 67);
    R4(c, d, e, a, b, 68);
    R4(b, c, d, e, a, 69);
    R4(a, b, c, d, e, 70);
    R4(e, a, b, c, d, 71);
    R4(d, e, a, b, c, 72);
    R4(c, d, e, a, b, 73);
    R4(b, c, d, e, a, 74);
    R4(a, b, c, d, e, 75);
    R4(e, a, b, c, d, 76);
    R4(d, e, a, b, c, 77);
    R4(c, d, e, a, b, 78);
    R4(b, c, d, e, a, 79);

    /* Add the working vars back into ctx.state[] */
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}

/* SHA1Init - Initialize new ctx */

void sha1_init(sha1_ctx *ctx)
{
    /* SHA1 initialization constants */
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    ctx->count = 0;
}

/* Run your data through this. */

void sha1_update(sha1_ctx *ctx, const uint8_t *data, size_t len)
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

        sha1_transform(ctx);
    }

    // Consume blocks from input buffer
    for (; p_data <= p_last_block; p_data += 64)
    {
        memcpy(&ctx->buffer[0], p_data, 64);
        sha1_transform(ctx);
    }

    // Store left-over buffer
    size_t left_over = p_end - p_data;
    if (left_over > 0)
    {
        memcpy(&ctx->buffer[0], p_data, left_over);
    }
}

/* Add padding and return the message digest. */

void sha1_final(sha1_ctx *ctx, uint8_t *digest)
{
    auto [padding, padding_size] = prepare_md_final_block<kSHA1BlockSize, true>(ctx->count);
    sha1_update(ctx, padding.data(), padding_size);
    state_to_digest<true>(digest, &ctx->state[0], sizeof(ctx->state) / sizeof(ctx->state[0]));
}

} // namespace parakeet_crypto::utils::hash

// NOLINTEND(*-avoid-c-arrays,*-magic-numbers,*-identifier-length)
