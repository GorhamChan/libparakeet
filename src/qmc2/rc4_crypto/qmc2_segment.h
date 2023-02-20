#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace parakeet_crypto::qmc2_rc4
{

class SegmentKeyImpl
{
  private:
    double hash_{0.0};

  public:
    SegmentKeyImpl(double hash) : hash_(hash)
    {
    }

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

        hash_ = static_cast<double>(hash);
    }

    [[nodiscard]] uint64_t GetKey(uint64_t segment_id, uint64_t seed) const
    {
        if (seed == 0)
        {
            return 0;
        }

        // Note: mul-then-div can cause the value to vary by 1.
        //       overflow/truncation was expected.
        constexpr double kMagic{100.0};
        return static_cast<uint64_t>(hash_ / static_cast<double>(seed * (segment_id + 1)) * kMagic);
    }
};

} // namespace parakeet_crypto::qmc2_rc4
