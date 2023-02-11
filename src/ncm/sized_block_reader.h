#pragma once

#include <algorithm>
#include <cstdint>
#include <utility>
#include <vector>

namespace parakeet_crypto::utils
{

class SizedBlockReader
{
  private:
    std::vector<uint8_t> &buffer_;
    size_t seek_counter_{0};
    size_t offset_;

  public:
    SizedBlockReader(std::vector<uint8_t> &buffer, size_t &offset) : buffer_(buffer), offset_(offset)
    {
    }

    inline bool Read(const uint8_t *&input, size_t &input_len, size_t required_len)
    {
        size_t copy_n = std::min(required_len - buffer_.size(), input_len);
        buffer_.insert(buffer_.end(), input, input + copy_n);
        offset_ += copy_n;
        input += copy_n;
        input_len -= copy_n;
        return buffer_.size() == required_len;
    }

    inline void SetSeekCounter(size_t len)
    {
        seek_counter_ = len;
    }

    inline bool Seek(const uint8_t *&input, size_t &input_len)
    {
        size_t seek_len = std::min(input_len, seek_counter_);
        input += seek_len;
        input_len -= seek_len;
        offset_ += seek_len;
        seek_counter_ -= seek_len;
        return seek_counter_ == 0;
    }
};

} // namespace parakeet_crypto::utils
