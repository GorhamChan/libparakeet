#pragma once

#include <cstddef>
#include <cstdint>

namespace parakeet_crypto::utils
{

class LoopIterator
{
  private:
    const uint8_t *begin_{nullptr};
    const uint8_t *end_{nullptr};
    const uint8_t *current_{nullptr};

  public:
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

    inline uint8_t GetAndMove()
    {
        auto result = Get();
        Next();
        return result;
    }

    inline void SetOffset(size_t offset)
    {
        current_ = begin_ + (offset % (end_ - begin_));
    }

    inline void Reset()
    {
        current_ = begin_;
    }
};

class LoopCounter
{
  private:
    size_t len_{0};
    size_t current_{0};

  public:
    LoopCounter(size_t len, size_t offset) : len_(len), current_(offset)
    {
    }

    inline bool Next()
    {
        current_++;
        if (current_ == len_)
        {
            current_ = 0;
            return true;
        }

        return false;
    }

    [[nodiscard]] inline size_t Get() const
    {
        return current_;
    }

    inline size_t GetAndMove()
    {
        auto result = Get();
        Next();
        return result;
    }

    inline void SetOffset(size_t offset)
    {
        current_ = offset % len_;
    }

    inline void Reset()
    {
        current_ = 0;
    }
};

} // namespace parakeet_crypto::utils
