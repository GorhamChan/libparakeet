#pragma once

// Adapted from: https://github.com/clibs/sha1/raw/d9ae30f34095107ece9dceb224839f0dc2f9c1c7/sha1.h
// License:      Public Domain

/*
   SHA-1 in C
   By Steve Reid <steve@edmweb.com>
   100% Public Domain
 */

#include <array>
#include <cstddef>
#include <cstdint>

namespace parakeet_crypto::utils::hash
{

constexpr size_t kSHA1BlockSize = 512 / 8; // = 64
constexpr size_t kSHA1DigestSize = 20;

// NOLINTBEGIN(*-c-arrays,*-magic-numbers)
/**
 * \private
 */
struct sha1_ctx
{
    uint64_t count;
    uint8_t buffer[kSHA1BlockSize];
    uint32_t state[5];
};
// NOLINTEND(*-c-arrays,*-magic-numbers)

void sha1_init(sha1_ctx *ctx);
void sha1_update(sha1_ctx *ctx, const uint8_t *data, size_t len);
void sha1_final(sha1_ctx *ctx, uint8_t *digest);

// Wrapper: C-style API
inline void sha1(uint8_t *digest, const uint8_t *p_input, size_t len)
{
    sha1_ctx ctx{};
    sha1_init(&ctx);
    sha1_update(&ctx, p_input, len);
    sha1_final(&ctx, digest);
}

// Wrapper: Array API from pointer
inline std::array<uint8_t, kSHA1DigestSize> sha1(const uint8_t *p_input, size_t len)
{
    std::array<uint8_t, kSHA1DigestSize> digest{};
    sha1(digest.data(), p_input, len);
    return digest;
}

// Wrapper: Array API
template <typename Container> inline std::array<uint8_t, kSHA1DigestSize> sha1(Container &&container)
{
    static_assert(sizeof(container[0]) == 1, "sha1: Container element should have size of 1");

    const auto *p_data = reinterpret_cast<const uint8_t *>(container.data()); // NOLINT(*-reinterpret-cast)
    return sha1(p_data, container.size());
}

} // namespace parakeet_crypto::utils::hash
