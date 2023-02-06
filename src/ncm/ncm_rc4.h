#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <numeric>

namespace parakeet_crypto::transformer
{

class NeteaseRC4
{
  private:
    static constexpr size_t kStateLen = 0x100;
    std::array<uint8_t, kStateLen> S_{};
    uint8_t i_{0};

  public:
    NeteaseRC4(const uint8_t *key, size_t key_len)
    {
        std::iota(S_.begin(), S_.end(), uint8_t{0});

        uint8_t j = 0; // NOLINT(readability-identifier-length)
        for (std::size_t i = 0; i < S_.size(); i++)
        {
            j += S_[i] + key[i % key_len];
            std::swap(S_[i], S_[j]);
        }
    }

    uint8_t Next()
    {
        i_++;

        uint8_t j = S_[i_] + i_; // NOLINT(readability-identifier-length)
        uint8_t index = S_[i_] + S_[j];
        return S_[index];
    }
};

} // namespace parakeet_crypto::transformer
