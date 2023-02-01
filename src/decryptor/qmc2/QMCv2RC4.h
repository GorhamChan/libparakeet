#pragma once

#include "QMCv2Utils.h"

#include <cassert>
#include <cstdint>

#include <algorithm>
#include <numeric>
#include <span>
#include <vector>

namespace parakeet_crypto::decryptor::tencent
{

class QMCv2RC4
{
  private:
    std::size_t segment_id_ = 0;

    double key_hash_ = 0;
    uint32_t i_ = 0;
    uint32_t j_ = 0;
    std::vector<uint8_t> key_;
    std::vector<uint8_t> S_;

    inline uint8_t DeriveByte()
    {
        // Set alias
        auto s = std::span{S_};
        auto n = s.size();

        i_ = (i_ + 1) % n;
        j_ = (s[i_] + j_) % n;
        std::swap(s[i_], s[j_]);

        return s[(s[i_] + s[j_]) % n];
    }

  public:
    inline void SetKey(std::span<const uint8_t> key, double key_hash)
    {
        key_hash_ = key_hash;
        key_.assign(key.begin(), key.end());
        key_hash_ = key_hash;
        S_.resize(key.size());
        NextSegment();
    }

    QMCv2RC4() = default;

    inline void DiscardBytes(std::size_t n)
    {
        while (n-- > 0)
        {
            DeriveByte();
        }
    }

    inline void NextSegment()
    {
        auto s = std::span{S_};
        auto key = std::span{key_};
        auto n = key.size();

        // Reset all
        i_ = j_ = 0;
        std::iota(s.begin(), s.end(), uint8_t{0});

        std::size_t j = 0;
        for (std::size_t i = 0; i < n; i++)
        {
            j = (s[i] + j + key[i % n]) % n;
            std::swap(s[i], s[j]);
        }

        auto segment_key = GetSegmentKey(key_hash_, segment_id_, uint64_t{key[segment_id_ & 0x1FF]});
        DiscardBytes(segment_key & 0x1FF);
        segment_id_++;
    }

    inline void Transform(std::span<uint8_t> dest, std::span<const uint8_t> src)
    {
        assert(("dest and src should have the same size", dest.size() == src.size()));

        const auto n = dest.size();
        for (std::size_t i = 0; i < n; i++)
        {
            dest[i] = src[i] ^ DeriveByte();
        }
    }
};

} // namespace parakeet_crypto::decryptor::tencent
