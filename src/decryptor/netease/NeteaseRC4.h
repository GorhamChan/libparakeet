#pragma once

#include <cstdint>

#include <algorithm>
#include <array>
#include <numeric>
#include <span>

namespace parakeet_crypto::decryptor::netease
{

class NeteaseRC4
{
  private:
    std::array<uint8_t, 0x100> S_;

  public:
    NeteaseRC4() = default;

    void Init(std::span<const uint8_t> key)
    {
        std::iota(S_.begin(), S_.end(), uint8_t{0});

        uint8_t j = 0;
        for (std::size_t i = 0; i < S_.size(); i++)
        {
            j += S_[i] + key[i % key.size()];
            std::swap(S_[i], S_[j]);
        }
    }

    void Derive(std::span<uint8_t> result)
    {
        uint8_t i = 0;
        for (auto &v : result)
        {
            i++;

            uint8_t j = S_[i] + i;
            uint8_t index = S_[i] + S_[j];
            v = S_[index];
        }
    }
};

} // namespace parakeet_crypto::decryptor::netease
