#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

namespace parakeet_crypto
{

template <size_t BlockSize> class BufferedTransform
{
  private:
    std::array<uint8_t, BlockSize> buffer_{};
    size_t idx_{};

  public:
    BufferedTransform() = default;

    template <typename T> void ProcessBuffer(const uint8_t *buffer, size_t n, T &&callback)
    {
        if (idx_ != 0)
        {
            size_t to_copy = std::min(BlockSize - idx_, n);
            std::copy_n(buffer, to_copy, &buffer_.at(idx_));
            n -= to_copy;
            buffer += to_copy;
            idx_ += to_copy;
            if (idx_ < BlockSize)
            {
                return;
            }

            idx_ = 0;
            if (!callback(buffer_.data()))
            {
                return;
            }
        }

        while (n > BlockSize)
        {
            if (!callback(buffer))
            {
                return;
            }
            buffer += BlockSize;
            n -= BlockSize;
        }

        if (n > 0)
        {
            std::copy_n(buffer, n, buffer_.data());
            idx_ += n;
        }
    }
};

} // namespace parakeet_crypto
