#include "parakeet-crypto/utils/hash/hmac_sha1.h"
#include <algorithm>

//    We define two fixed and different strings ipad and opad as follows
//    (the 'i' and 'o' are mnemonics for inner and outer):

//                    ipad = the byte 0x36 repeated B times
//                   opad = the byte 0x5C repeated B times.

//    To compute HMAC over the data `text' we perform

//                     H(K XOR opad, H(K XOR ipad, text))

namespace parakeet_crypto::utils::hash
{

void hmac_sha1_init(hmac_sha1_ctx *ctx, const uint8_t *p_key, size_t key_len)
{
    sha1_init(&ctx->sha1_outer);
    sha1_init(&ctx->sha1_inner);

    std::array<uint8_t, kSHA1BlockSize> secret{}; // this will be K'
    if (key_len > secret.size())
    {
        auto key_digest = sha1(p_key, key_len);
        std::copy(key_digest.cbegin(), key_digest.cend(), secret.begin());
    }
    else
    {
        std::copy_n(p_key, key_len, secret.begin());
    }

    constexpr uint8_t kOuterPadByte = 0x5C;
    constexpr uint8_t kInnerPadByte = 0x36;

    // Outer pad
    std::transform(secret.cbegin(), secret.cend(), secret.begin(), //
                   [&](auto byte) { return byte ^ kOuterPadByte; });
    sha1_update(&ctx->sha1_outer, secret.data(), secret.size());

    // Inner pad
    std::transform(secret.cbegin(), secret.cend(), secret.begin(), //
                   [&](auto byte) { return byte ^ kOuterPadByte ^ kInnerPadByte; });
    sha1_update(&ctx->sha1_inner, secret.data(), secret.size());
}

void hmac_sha1_final(hmac_sha1_ctx *ctx, uint8_t *digest)
{
    sha1_final(&ctx->sha1_inner, digest);
    sha1_update(&ctx->sha1_outer, digest, kSHA1DigestSize);
    sha1_final(&ctx->sha1_outer, digest);
}

} // namespace parakeet_crypto::utils::hash
