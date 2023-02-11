#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace parakeet_crypto::qmc2_rc4
{

class SegmentKeyImpl
{
  private:
    uint64_t hash_{0};

  public:
    SegmentKeyImpl(const uint8_t *key, size_t key_len)
    {
        uint32_t hash = 1;
        const auto *end = key + key_len;
        for (const auto *it = key; it < end; it++)
        {
            uint32_t value = *it;
            if (value == 0)
            {
                continue;
            }

            uint32_t next_hash = hash * value;
            if (next_hash == 0 || next_hash < hash)
            {
                break;
            }
            hash = next_hash;
        }

        constexpr uint64_t kMagic{100};
        hash_ = kMagic * hash;
    }

    [[nodiscard]] uint64_t GetKey(uint64_t segment_id, uint64_t seed) const
    {
        if (seed == 0)
        {
            return 0;
        }

        return hash_ / (seed * (segment_id + 1));
    }
};

} // namespace parakeet_crypto::qmc2_rc4
