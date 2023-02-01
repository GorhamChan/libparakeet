#pragma once

#include <cstddef>

#include <algorithm>
#include <span>
#include <string>
#include <vector>

namespace parakeet_crypto::decryptor
{

class StreamDecryptor
{
  public:
    StreamDecryptor() = default;
    virtual ~StreamDecryptor() = default;

    /**
     * @brief Write encrypted data stream to the file loader.
     *
     * @param in
     * @param len
     */
    virtual bool Write(const uint8_t *in, std::size_t len) = 0;

    /**
     * @brief Notify stream transformer that we have reached end of file.
     */
    virtual bool End() = 0;

    virtual std::string GetName() const = 0;

    /**
     * @brief Return true if the decryptor is in an error state.
     *
     * @return true
     * @return false
     */
    virtual bool InErrorState() const
    {
        return !error_.empty();
    }

    /**
     * @brief Get the Error Message object
     *
     * @return const std::string&
     */
    virtual const std::string &GetErrorMessage() const
    {
        return error_;
    }

    inline std::size_t GetOutputSize() const
    {
        return buf_out_.size();
    }

    inline std::size_t PeekDecryptedContent(std::span<uint8_t> content)
    {
        std::size_t len = std::min(buf_out_.size(), content.size());
        std::copy_n(buf_out_.begin(), len, content.begin());
        return len;
    }

    inline std::size_t ReadDecryptedContent(std::span<uint8_t> content)
    {
        std::size_t len = std::min(buf_out_.size(), content.size());
        std::copy_n(buf_out_.begin(), len, content.begin());
        buf_out_.erase(buf_out_.begin(), buf_out_.begin() + len);
        return len;
    }

    inline void ReadAllDecryptedContent(std::vector<uint8_t> &out)
    {
        out = std::move(buf_out_);
    }

  protected:
    std::size_t offset_ = 0;
    std::string error_ = "";

    std::vector<uint8_t> buf_in_;
    std::vector<uint8_t> buf_out_;

    /**
     * @brief Encrypted file - header/offset process helper.
     *        Once header is processed, you should reset `buf_in_`.
     *
     * @param p Pointer to input buffer.
     * @param len input buf size.
     * @param offset bytes to read until reaching this offset.
     * @return true `buf_in_` now contains enough header data.
     * @return false Nothing to do.
     */
    inline bool ReadUntilOffset(const uint8_t *&p, std::size_t &len, std::size_t target_offset)
    {
        if (offset_ < target_offset)
        {
            auto read_size = std::min(target_offset - offset_, len);
            if (read_size == 0)
                return false;

            buf_in_.insert(buf_in_.end(), p, p + read_size);

            offset_ += read_size;
            p += read_size;
            len -= read_size;
        }

        return offset_ == target_offset;
    }

    /**
     * @brief Keep reading data from p to buf_in_, until it reaches block_size.
     *        Once block is processed, you should reset `buf_in_`.
     *
     * @param p
     * @param len
     * @param block_size
     * @return true
     * @return false
     */
    inline bool ReadBlock(const uint8_t *&p, std::size_t &len, std::size_t block_size)
    {
        if (buf_in_.size() < block_size)
        {
            auto read_size = std::min(block_size - buf_in_.size(), len);
            if (read_size == 0)
                return false;

            buf_in_.insert(buf_in_.end(), p, p + read_size);

            p += read_size;
            len -= read_size;
        }

        return buf_in_.size() == block_size;
    }

    inline uint8_t *ExpandOutputBuffer(std::size_t len)
    {
        std::size_t pos = buf_out_.size();
        buf_out_.resize(pos + len);
        return &buf_out_[pos];
    }

    inline void EraseInput(std::size_t len)
    {
        // Prevent auto format to one-liner
        buf_in_.erase(buf_in_.begin(), buf_in_.begin() + len);
    }

    inline void ConsumeInput(std::size_t len)
    {
        EraseInput(len);
        offset_ += len;
    }

    inline void ConsumeInput(std::span<uint8_t> input_buffer)
    {
        const auto len = input_buffer.size();
        std::copy_n(buf_in_.begin(), len, input_buffer.begin());
        ConsumeInput(len);
    }

    inline void ConsumeInput(uint32_t *value)
    {
        ConsumeInput(std::span{(uint8_t *)value, sizeof(*value)});
    }
};

} // namespace parakeet_crypto::decryptor
