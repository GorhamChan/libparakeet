// Adapted from: https://github.com/Zunawe/md5-c/raw/f3529b666b7ae8b80b0a9fa88ac2a91b389909c7/md5.h
// License:      The Unlicense

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace parakeet_crypto::utils::hash
{

constexpr size_t kMD5BlockSize = 512 / 8;
constexpr size_t kMD5DigestSize = 16;

// NOLINTBEGIN(*-c-arrays,*-magic-numbers)
struct md5_ctx
{
    uint64_t count;                // Size of input in bytes
    uint8_t buffer[kMD5BlockSize]; // Input to be used in the next step
    uint32_t state[4];             // Current accumulation of hash
};
// NOLINTEND(*-c-arrays,*-magic-numbers)

void md5_init(md5_ctx *ctx);
void md5_update(md5_ctx *ctx, const uint8_t *data, size_t len);
void md5_final(md5_ctx *ctx, uint8_t *digest);
void md5_transform(uint32_t *buffer, uint32_t *input);

// Wrapper: C-style API
inline void md5(uint8_t *digest, const uint8_t *p_input, size_t len)
{
    md5_ctx ctx{};
    md5_init(&ctx);
    md5_update(&ctx, p_input, len);
    md5_final(&ctx, digest);
}

// Wrapper: Array API from pointer
inline std::array<uint8_t, kMD5DigestSize> md5(const uint8_t *p_input, size_t len)
{
    std::array<uint8_t, kMD5DigestSize> digest{};
    md5(digest.data(), p_input, len);
    return digest;
}

// Wrapper: Array API
template <typename Container> inline std::array<uint8_t, kMD5DigestSize> md5(Container &&container)
{
    static_assert(sizeof(container[0]) == 1, "md5: Container element should have size of 1");

    const auto *p_data = reinterpret_cast<const uint8_t *>(container.data()); // NOLINT(*-reinterpret-cast)
    return md5(p_data, container.size());
}

} // namespace parakeet_crypto::utils::hash
