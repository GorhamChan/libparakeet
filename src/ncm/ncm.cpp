#include "ncm_key_utils.h"

#include "parakeet-crypto/ITransformer.h"
#include "parakeet-crypto/transformer/ncm.h"
#include "utils/EndianHelper.h"
#include "utils/SizedBlockReader.h"
#include "utils/XorHelper.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <vector>

namespace parakeet_crypto::transformer
{

/**
 * \file
 * \brief NCM file format
 *
 *   - Header: {43 54 45 4E 46 44 41 4D - "CTENFDAM"}
 *   - Padding (2 bytes)
 *   - SizedBlock: Content Key (encrypted)
 *   - SizedBlock: Metadata; (encrypted; ignored)
 *   - Padding (9 bytes)
 *   - SizedBlock: Album Cover (ignored);
 *   - Audio Data (Encrypted with Content Key);
 */

class NCMTransformer : public ITransformer
{
  private:
    static constexpr size_t kHeaderPadding{2};
    static constexpr size_t kCoverPadding{9};

    std::array<uint8_t, kNCMContentKeySize> content_key_{};
    enum class State
    {
        WAITING_FOR_HEADER = 0,
        SEEK_PADDING_HEADER,

        READ_CONTENT_KEY_LEN,
        READ_CONTENT_KEY,

        READ_METADATA_LEN,
        SEEK_METADATA,

        SEEK_PADDING_COVER,
        READ_COVER_LEN,
        SEEK_COVER,

        CONTENT_DECRYPTION,
    };
    State state_{State::WAITING_FOR_HEADER};
    size_t offset_{0};
    size_t audio_data_offset_{0};

    std::array<uint8_t, kNCMFinalKeyLen> audio_xor_key_{};
    std::vector<uint8_t> buffer_{};
    size_t next_block_size_{0};
    utils::SizedBlockReader sized_reader_{buffer_, offset_};
    inline void ResetForNextSizedBuffer(size_t seek_counter = 0)
    {
        buffer_.resize(0);
        next_block_size_ = 0;
        sized_reader_.SetSeekCounter(seek_counter);
    }

    TransformResult HandleHeader(                                    //
        size_t &bytes_written, uint8_t *&output, size_t &output_len, // NOLINT(misc-unused-parameters)
        const uint8_t *&input, size_t &input_len)                    // NOLINT(misc-unused-parameters)
    {
        constexpr static std::array<const uint8_t, 8> kHeader{'C', 'T', 'E', 'N', 'F', 'D', 'A', 'M'};

        if (sized_reader_.Read(input, input_len, kHeader.size()))
        {
            if (!std::equal(kHeader.begin(), kHeader.end(), buffer_.begin()))
            {
                return TransformResult::ERROR_INVALID_FORMAT;
            }

            ResetForNextSizedBuffer(kHeaderPadding);
            state_ = State::SEEK_PADDING_HEADER;
        }

        return TransformResult::OK;
    }

    TransformResult HandleSeekHeaderPadding(                         //
        size_t &bytes_written, uint8_t *&output, size_t &output_len, // NOLINT(misc-unused-parameters)
        const uint8_t *&input, size_t &input_len)                    // NOLINT(misc-unused-parameters)
    {
        if (sized_reader_.Seek(input, input_len))
        {
            ResetForNextSizedBuffer();
            state_ = State::READ_CONTENT_KEY_LEN;
        }

        return TransformResult::OK;
    }

    TransformResult HandleReadContentKeyLen(                         //
        size_t &bytes_written, uint8_t *&output, size_t &output_len, // NOLINT(misc-unused-parameters)
        const uint8_t *&input, size_t &input_len)                    // NOLINT(misc-unused-parameters)
    {
        if (sized_reader_.Read(input, input_len, sizeof(uint32_t)))
        {
            auto next_block_size = ReadLittleEndian<uint32_t>(buffer_.data());
            ResetForNextSizedBuffer();
            next_block_size_ = next_block_size;
            state_ = State::READ_CONTENT_KEY;
        }

        return TransformResult::OK;
    }

    TransformResult HandleReadContentKey(                            //
        size_t &bytes_written, uint8_t *&output, size_t &output_len, // NOLINT(misc-unused-parameters)
        const uint8_t *&input, size_t &input_len)                    // NOLINT(misc-unused-parameters)
    {
        if (sized_reader_.Read(input, input_len, next_block_size_))
        {
            auto key = DecryptNCMAudioKey(buffer_, content_key_);
            if (!key.has_value())
            {
                return TransformResult::ERROR_INVALID_KEY;
            }

            audio_xor_key_ = *key;
            ResetForNextSizedBuffer();
            state_ = State::READ_METADATA_LEN;
        }
        return TransformResult::OK;
    }

    TransformResult HandleReadMetadataLen(                           //
        size_t &bytes_written, uint8_t *&output, size_t &output_len, // NOLINT(misc-unused-parameters)
        const uint8_t *&input, size_t &input_len)                    // NOLINT(misc-unused-parameters)
    {
        if (sized_reader_.Read(input, input_len, sizeof(uint32_t)))
        {
            ResetForNextSizedBuffer(ReadLittleEndian<uint32_t>(buffer_.data()));
            state_ = State::SEEK_METADATA;
        }

        return TransformResult::OK;
    }

    TransformResult HandleSeekMetadata(                              //
        size_t &bytes_written, uint8_t *&output, size_t &output_len, // NOLINT(misc-unused-parameters)
        const uint8_t *&input, size_t &input_len)                    // NOLINT(misc-unused-parameters)
    {
        if (sized_reader_.Seek(input, input_len))
        {
            ResetForNextSizedBuffer(kCoverPadding);
            state_ = State::SEEK_PADDING_COVER;
        }
        return TransformResult::OK;
    }

    TransformResult HandleSeekCoverPadding(                          //
        size_t &bytes_written, uint8_t *&output, size_t &output_len, // NOLINT(misc-unused-parameters)
        const uint8_t *&input, size_t &input_len)                    // NOLINT(misc-unused-parameters)
    {
        if (sized_reader_.Seek(input, input_len))
        {
            ResetForNextSizedBuffer();
            state_ = State::READ_COVER_LEN;
        }

        return TransformResult::OK;
    }

    TransformResult HandleReadCoverLen(                              //
        size_t &bytes_written, uint8_t *&output, size_t &output_len, // NOLINT(misc-unused-parameters)
        const uint8_t *&input, size_t &input_len)                    // NOLINT(misc-unused-parameters)
    {
        if (sized_reader_.Read(input, input_len, sizeof(uint32_t)))
        {
            ResetForNextSizedBuffer(ReadLittleEndian<uint32_t>(buffer_.data()));
            state_ = State::SEEK_COVER;
        }

        return TransformResult::OK;
    }

    TransformResult HandleSeekCover(                                 //
        size_t &bytes_written, uint8_t *&output, size_t &output_len, // NOLINT(misc-unused-parameters)
        const uint8_t *&input, size_t &input_len)                    // NOLINT(misc-unused-parameters)
    {
        if (sized_reader_.Seek(input, input_len))
        {
            ResetForNextSizedBuffer();
            state_ = State::CONTENT_DECRYPTION;
        }
        return TransformResult::OK;
    }

    TransformResult HandleDecryption(                                //
        size_t &bytes_written, uint8_t *&output, size_t &output_len, // NOLINT(misc-unused-parameters)
        const uint8_t *&input, size_t &input_len)                    // NOLINT(misc-unused-parameters)
    {
        utils::XorFromOffset(output, input, input_len, audio_xor_key_.data(), audio_xor_key_.size(),
                             audio_data_offset_);
        audio_data_offset_ += input_len;
        bytes_written += input_len;
        output_len -= input_len;
        input_len = 0;
        return TransformResult::OK;
    }

  public:
    NCMTransformer(const uint8_t *content_key) : ITransformer()
    {
        std::copy_n(content_key, content_key_.size(), content_key_.begin());
    }

    TransformResult Transform(uint8_t *output, size_t &output_len, const uint8_t *input, size_t input_len) override
    {

        if (output_len < input_len)
        {
            output_len = input_len;
            return TransformResult::ERROR_INSUFFICIENT_OUTPUT;
        }

        size_t bytes_written{0};
        TransformResult result{TransformResult::OK};
        while (result == TransformResult::OK && input_len > 0)
        {
            switch (state_)
            {
            case State::WAITING_FOR_HEADER:
                result = HandleHeader(bytes_written, output, output_len, input, input_len);
                break;
            case State::SEEK_PADDING_HEADER:
                result = HandleSeekHeaderPadding(bytes_written, output, output_len, input, input_len);
                break;
            case State::READ_CONTENT_KEY_LEN:
                result = HandleReadContentKeyLen(bytes_written, output, output_len, input, input_len);
                break;
            case State::READ_CONTENT_KEY:
                result = HandleReadContentKey(bytes_written, output, output_len, input, input_len);
                break;
            case State::READ_METADATA_LEN:
                result = HandleReadMetadataLen(bytes_written, output, output_len, input, input_len);
                break;
            case State::SEEK_METADATA:
                result = HandleSeekMetadata(bytes_written, output, output_len, input, input_len);
                break;
            case State::SEEK_PADDING_COVER:
                result = HandleSeekCoverPadding(bytes_written, output, output_len, input, input_len);
                break;
            case State::READ_COVER_LEN:
                result = HandleReadCoverLen(bytes_written, output, output_len, input, input_len);
                break;
            case State::SEEK_COVER:
                result = HandleSeekCover(bytes_written, output, output_len, input, input_len);
                break;
            case State::CONTENT_DECRYPTION:
                result = HandleDecryption(bytes_written, output, output_len, input, input_len);
                break;
            }
        }
        output_len = bytes_written;
        return result;
    }
};

std::unique_ptr<ITransformer> CreateNeteaseNCMDecryptionTransformer(const uint8_t *content_key)
{
    return std::make_unique<NCMTransformer>(content_key);
}

} // namespace parakeet_crypto::transformer
