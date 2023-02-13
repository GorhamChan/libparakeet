#pragma once

#include <cstddef>
#include <cstdint>

namespace parakeet_crypto::utils
{

template <typename ItemType = uint8_t> class LoopIterator
{
  private:
    const ItemType *begin_{nullptr};
    const ItemType *end_{nullptr};
    const ItemType *current_{nullptr};

  public:
    LoopIterator(const ItemType *ptr, size_t len, size_t offset)
        : begin_(ptr), current_(ptr + (offset % len)), end_(ptr + len)
    {
    }
    template <typename Container>
    LoopIterator(Container container, size_t offset) : LoopIterator(container.data(), container.size(), offset)
    {
    }

    inline ItemType Get()
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

    inline ItemType GetAndMove()
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
