#pragma once

#include <cstdint>
#include <span>

namespace parakeet_crypto::decryptor::tencent
{

constexpr auto HashQMCv2Key(std::span<const std::uint8_t> key) -> uint32_t
{
    uint32_t hash = 1;
    for (auto value : key)
    {
        // ignore if key char is '\x00'
        if (value == uint8_t{0})
            continue;

        const uint32_t next_hash = hash * int32_t{value};
        if (next_hash == 0 || next_hash <= hash)
            break;

        hash = next_hash;
    }

    return hash;
}

constexpr auto GetSegmentKey(double key_hash, uint64_t segment_id, uint64_t seed) -> uint64_t
{
    // HACK: Workaround incorrect behaviour when divided by 0.
    if (seed == 0)
    {
        return 0;
    }

    return static_cast<uint64_t>(key_hash / double((segment_id + 1) * seed) * 100.0);
}

} // namespace parakeet_crypto::decryptor::tencent
