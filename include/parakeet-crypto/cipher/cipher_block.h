#pragma once

#include "cipher.h"
#include "cipher_error.h"

#include <algorithm>

namespace parakeet_crypto::cipher
{

template <size_t kBlockSize> class BlockCipher : public Cipher
{
  protected:
    // NOLINTBEGIN(*-non-private-member-variables-in-classes)
    std::array<uint8_t, kBlockSize> block_{};
    size_t block_offset_ = 0;
    // NOLINTEND(*-non-private-member-variables-in-classes)

  public:
    constexpr static size_t block_size_ = kBlockSize;
    ~BlockCipher() override = default;

    [[nodiscard]] virtual CipherErrorCode TransformBlock(uint8_t *buffer) = 0;
    [[nodiscard]] inline CipherErrorCode TransformBlocks(uint8_t *buffer, size_t n)
    {
        if (n % kBlockSize != 0)
        {
            return CipherError::kIncompleteInputData;
        }

        auto *p_end = buffer + n;
        while (buffer < p_end)
        {
            if (auto err = TransformBlock(buffer); err != CipherError::kSuccess)
            {
                return err;
            }
            buffer += kBlockSize;
        }

        return CipherError::kSuccess;
    }
    template <typename Container> [[nodiscard]] inline CipherErrorCode TransformBlocks(Container &buffer)
    {
        return TransformBlocks(buffer.data(), buffer.size());
    }

    [[nodiscard]] CipherErrorCode Update(uint8_t *output, size_t &n_output, const uint8_t *input, size_t n) override
    {
        size_t total_input_block_count = ((block_offset_ == 0 ? 0 : kBlockSize - block_offset_) + n) / kBlockSize;
        size_t expected_output_size = total_input_block_count * kBlockSize;
        if (n_output < expected_output_size)
        {
            n_output = expected_output_size;
            return CipherError::kOutputBufferTooSmall;
        }
        n_output = 0;
        if (n == 0)
        {
            return CipherError::kSuccess;
        }

        if (block_offset_ != 0)
        {
            auto len_process = std::min(n, kBlockSize - block_offset_);
            std::copy_n(input, len_process, &block_[block_offset_]);
            block_offset_ += len_process;
            input += len_process;
            n -= len_process;

            if (block_offset_ == kBlockSize)
            {
                std::copy(block_.begin(), block_.end(), output);
                if (auto err = TransformBlock(output); err != CipherError::kSuccess)
                {
                    return err;
                }
                output += kBlockSize;
                n_output += kBlockSize;
                block_offset_ = 0;
            }
        }

        while (n >= kBlockSize)
        {
            std::copy_n(input, kBlockSize, output);
            if (auto err = TransformBlock(output); err != CipherError::kSuccess)
            {
                return err;
            }
            output += kBlockSize;
            n_output += kBlockSize;
            input += kBlockSize;
            n -= kBlockSize;
        }

        if (n != 0)
        {
            std::copy_n(input, n, &block_[block_offset_]);
            block_offset_ += n;
        }

        return CipherError::kSuccess;
    };

    [[nodiscard]] CipherErrorCode Final(uint8_t * /*output*/, size_t & /*n_output*/) override
    {
        if (block_offset_ != 0)
        {
            return CipherError::kIncompleteInputData;
        }

        return CipherError::kSuccess;
    }
};

} // namespace parakeet_crypto::cipher