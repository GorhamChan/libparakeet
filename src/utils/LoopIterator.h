#pragma once

#include <cstddef>
#include <cstdint>

namespace parakeet_crypto::kgm
{

class LoopIterator
{
  private:
    const uint8_t *begin_{nullptr};
    const uint8_t *end_{nullptr};
    const uint8_t *current_{nullptr};

  public:
    virtual ~LoopIterator() = default;
    LoopIterator(const uint8_t *ptr, size_t len, size_t offset)
        : begin_(ptr), current_(ptr + (offset % len)), end_(ptr + len)
    {
    }

    inline uint8_t Get()
    {
        return *current_;
    }

    /**
     * @brief Move forward
     *
     * @return true Loop reset.
     * @return false Loop did not reset.
     */
    inline bool Next()
    {
        current_++;
        if (current_ == end_)
        {
            current_ = begin_;
            return true;
        }

        return false;
    }
};

} // namespace parakeet_crypto::kgm
