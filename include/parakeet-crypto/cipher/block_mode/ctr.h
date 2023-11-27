#pragma once

#include "parakeet-crypto/cipher/cipher.h"
#include "parakeet-crypto/cipher/cipher_block.h"
#include "parakeet-crypto/cipher/cipher_error.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <stdexcept>

namespace parakeet_crypto::cipher::block_mode
{

namespace ctr_impl_details
{

// Same behaviour as OpenSSL's CTR IV incrementation
template <typename Container> inline void increment_iv(Container &iv_array)
{
    for (auto it = iv_array.rbegin(); it != iv_array.rend(); ++it)
    {
        if (++(*it) != 0)
        {
            break;
        }
    }
}

inline void xor_bytes(uint8_t *output, const uint8_t *input, size_t n)
{
    while (n-- != 0)
    {
        *output++ ^= *input++;
    }
}

inline void xor_bytes(uint8_t *output, const uint8_t *input, const uint8_t *src2, size_t n)
{
    while (n-- != 0)
    {
        *output++ = *input++ ^ *src2++;
    }
}

}; // namespace ctr_impl_details

template <typename ParentCipher> class CTR : public BlockCipher<ParentCipher::block_size_>
{
  public:
    // NOLINTNEXTLINE(*-identifier-length)
    CTR(std::shared_ptr<ParentCipher> cipher, const uint8_t *iv) : cipher_(cipher)
    {
        if (cipher == nullptr)
        {
            throw std::invalid_argument("cipher cannot be nullptr");
        }

        std::copy_n(iv, ParentCipher::block_size_, iv_.begin());
    }

    [[nodiscard]] CipherErrorCode TransformBlock(uint8_t *buffer)
    {
        auto current_iv = iv_;
        if (auto err = cipher_->TransformBlock(current_iv.data()); err != CipherError::kSuccess)
        {
            return err;
        }
        ctr_impl_details::xor_bytes(buffer, current_iv.data(), ParentCipher::block_size_);
        ctr_impl_details::increment_iv(iv_);
        return CipherError::kSuccess;
    }

  private:
    std::shared_ptr<ParentCipher> cipher_;
    std::array<uint8_t, ParentCipher::block_size_> iv_{};
};

/**
 * Create a CTR_Stream cipher.
 */
template <typename ParentCipher> class CTR_Stream : public Cipher
{
  public:
    // NOLINTNEXTLINE(*-identifier-length)
    CTR_Stream(std::shared_ptr<ParentCipher> cipher, const uint8_t *iv) : cipher_(cipher)
    {
        if (cipher == nullptr)
        {
            throw std::invalid_argument("cipher cannot be nullptr");
        }

        std::copy_n(iv, ParentCipher::block_size_, iv_.begin());
    }

    // Seek from current position, positive offset only.
    // This is used to update the IV in CTR mode.
    inline CipherErrorCode Skip(size_t count)
    {
        if (auto bytes_left = GetBufferBytesLeft(); bytes_left > 0)
        {
            auto skip_len = std::min(count, bytes_left);
            count -= skip_len;
            buffer_offset_ = (buffer_offset_ + skip_len) % ParentCipher::block_size_;
        }

        if (count >= ParentCipher::block_size_)
        {
            buffer_offset_ = 0;
        }
        while (count >= ParentCipher::block_size_)
        {
            count -= ParentCipher::block_size_;
            if (auto err = IncrementCounter(); err != CipherError::kSuccess)
            {
                return err;
            }
        }

        if (count > 0)
        {
            if (auto err = IncrementCounter(); err != CipherError::kSuccess)
            {
                return err;
            }
            buffer_offset_ = count;
        }

        return CipherError::kSuccess;
    }

    [[nodiscard]] CipherErrorCode Update(uint8_t *output, size_t &n_output, const uint8_t *input, size_t n) override
    {
        if (n_output < n)
        {
            n_output = n;
            return CipherError::kOutputBufferTooSmall;
        }
        n_output = 0;
        if (n == 0)
        {
            return CipherError::kSuccess;
        }

        auto increment_by_length = [&](size_t len) {
            n -= len;
            n_output += len;
            output += len;
            input += len;
            buffer_offset_ = (buffer_offset_ + len) % ParentCipher::block_size_;
        };

        if (auto bytes_left = GetBufferBytesLeft(); bytes_left > 0)
        {
            auto process_len = std::min(n, bytes_left);
            ctr_impl_details::xor_bytes(output, input, &buffer_[buffer_offset_], process_len);
            increment_by_length(process_len);
        }

        while (n > 0)
        {
            auto process_len = std::min(n, ParentCipher::block_size_);
            if (auto err = IncrementCounter(); err != CipherError::kSuccess)
            {
                return err;
            }
            ctr_impl_details::xor_bytes(output, input, buffer_.data(), process_len);
            increment_by_length(process_len);
        }

        return CipherError::kSuccess;
    }

    /**
     * Finalize the block cipher.
     * @param output Pointer to the output buffer. Sometimes it can be nullptr.
     * @param n_output Pointer to the number of bytes available in the output buffer. It will be updated with the
     *                 number of bytes written to the output buffer.
     * @return Error code. 0 for success, otherwise an error code.
     */
    [[nodiscard]] CipherErrorCode Final(uint8_t * /*output*/, size_t & /*n_output*/) override
    {
        return CipherError::kSuccess;
    }

  private:
    std::shared_ptr<ParentCipher> cipher_;
    std::array<uint8_t, ParentCipher::block_size_> iv_{};
    std::array<uint8_t, ParentCipher::block_size_> buffer_{};
    size_t buffer_offset_{0};
    inline size_t GetBufferBytesLeft()
    {
        return buffer_offset_ == 0 ? 0 : ParentCipher::block_size_ - buffer_offset_;
    }
    inline CipherErrorCode IncrementCounter()
    {
        buffer_ = iv_;
        if (auto err = cipher_->TransformBlock(buffer_.data()); err != CipherError::kSuccess)
        {
            return err;
        }
        ctr_impl_details::increment_iv(iv_);
        return CipherError::kSuccess;
    }
};

}; // namespace parakeet_crypto::cipher::block_mode
