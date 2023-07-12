#pragma once
#include "sha1.h"

namespace parakeet_crypto::utils::hash
{

// NOLINTBEGIN(*-c-arrays,*-magic-numbers)
/**
 * \private
 */
struct hmac_sha1_ctx
{
    sha1_ctx sha1_outer;
    sha1_ctx sha1_inner;
};
// NOLINTEND(*-c-arrays,*-magic-numbers)

void hmac_sha1_init(hmac_sha1_ctx *ctx, const uint8_t *p_key, size_t key_len);
inline void hmac_sha1_update(hmac_sha1_ctx *ctx, const uint8_t *data, size_t len)
{
    sha1_update(&ctx->sha1_inner, data, len);
}
void hmac_sha1_final(hmac_sha1_ctx *ctx, uint8_t *digest);

// Wrapper: C-style API
inline void hmac_sha1(uint8_t *digest, const uint8_t *p_input, size_t len, const uint8_t *p_key, size_t key_len)
{
    hmac_sha1_ctx ctx{};
    hmac_sha1_init(&ctx, p_key, key_len);
    hmac_sha1_update(&ctx, p_input, len);
    hmac_sha1_final(&ctx, digest);
}

// Wrapper: Array API from pointer
inline std::array<uint8_t, kSHA1DigestSize> hmac_sha1(const uint8_t *p_input, size_t len, //
                                                      const uint8_t *p_key, size_t key_len)
{
    std::array<uint8_t, kSHA1DigestSize> digest{};
    hmac_sha1(digest.data(), p_input, len, p_key, key_len);
    return digest;
}

// Wrapper: Array API
template <typename Container, typename KeyContainer>
inline std::array<uint8_t, kSHA1DigestSize> hmac_sha1(Container &&container, KeyContainer &&key)
{
    static_assert(sizeof(container[0]) == 1, "hmac_sha1: Container element should have size of 1");
    static_assert(sizeof(container[0]) == 1, "hmac_sha1: KeyContainer element should have size of 1");

    const auto *p_data = reinterpret_cast<const uint8_t *>(container.data()); // NOLINT(*-reinterpret-cast)
    const auto *p_key = reinterpret_cast<const uint8_t *>(key.data());        // NOLINT(*-reinterpret-cast)
    return hmac_sha1(p_data, container.size(), p_key, key.size());
}

} // namespace parakeet_crypto::utils::hash
