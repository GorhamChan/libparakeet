#include "kuwo_common.h"
#include "parakeet-crypto/transformer/kuwo.h"

#include "parakeet-crypto/ITransformer.h"

#include "utils/EndianHelper.h"
#include "utils/StringHelper.h"
#include "utils/XorHelper.h"

#include <cinttypes>
#include <cstdint>

#include <algorithm>
#include <array>
#include <memory>
#include <vector>

namespace parakeet_crypto::transformer
{

class KuwoDecryptionTransformer : public ITransformer
{
  private:
    enum class State
    {
        PROCESS_HEADER,
        SEEK_TO_BODY,
        DECRYPTION,
    };

    State state_ = State::PROCESS_HEADER;
    size_t offset_ = 0;
    std::array<uint8_t, kKuwoDecryptionKeySize> key_{};
    KuwoHeaderUnion file_header_{};

  public:
    KuwoDecryptionTransformer(const uint8_t *key) : ITransformer()
    {
        std::copy_n(key, kKuwoDecryptionKeySize, key_.begin());
    }

    TransformResult Transform(uint8_t *output, size_t &output_len, const uint8_t *input, size_t input_len) override
    {
        size_t bytes_written = 0;
        auto result = TransformResult::OK;
        while (input_len > 0 && result == TransformResult::OK)
        {
            switch (state_)
            {
            case State::PROCESS_HEADER:
                result = ProcessHeader(input, input_len);
                break;
            case State::SEEK_TO_BODY:
                result = SeekToBody(input, input_len);
                break;
            case State::DECRYPTION:
                result = DecryptBuffer(bytes_written, output, output_len, input, input_len);
                break;
            }
        }

        output_len = bytes_written;
        return result;
    }

    TransformResult DecryptBuffer(size_t &bytes_written, uint8_t *&output, size_t &output_len, const uint8_t *&input,
                                  size_t &input_len)
    {
        if (input_len > output_len)
        {
            bytes_written += input_len;
            return TransformResult::ERROR_INSUFFICIENT_OUTPUT;
        }

        utils::XorFromOffset(output, input, input_len, key_.data(), key_.size(), offset_);

        bytes_written += input_len;
        output += input_len;
        output_len -= input_len;
        input += input_len;
        input_len -= input_len;

        return TransformResult::OK;
    }

    TransformResult ProcessHeader(const uint8_t *&input, size_t &input_len)
    {
        auto copy_n = std::min(input_len, sizeof(KuwoHeader) - offset_);
        std::copy_n(input, copy_n, &file_header_.as_bytes[offset_]);
        input += copy_n;
        input_len -= copy_n;
        offset_ += copy_n;

        if (offset_ == sizeof(KuwoHeader))
        {
            if (!std::equal(kKnownKuwoHeader1.begin(), kKnownKuwoHeader1.end(), &file_header_.as_header.header[0]) &&
                !std::equal(kKnownKuwoHeader2.begin(), kKnownKuwoHeader2.end(), &file_header_.as_header.header[0]))
            {
                return TransformResult::ERROR_INVALID_FORMAT;
            }

            auto resource_id = SwapLittleEndianToHost(file_header_.as_header.resource_id);
            SetupKuwoDecryptionKey(resource_id, key_.begin(), key_.end());

            // Next state: seek to content body.
            state_ = State::SEEK_TO_BODY;
        }

        return TransformResult::OK;
    }

    TransformResult SeekToBody(const uint8_t *&input, size_t &input_len)
    {
        size_t required_bytes = kFullKuwoHeaderLen - offset_;
        size_t seek_len = std::min(input_len, required_bytes);
        offset_ += seek_len;
        input += seek_len;
        input_len -= seek_len;

        if (offset_ == kFullKuwoHeaderLen)
        {
            state_ = State::DECRYPTION;
        }

        return TransformResult::OK;
    }
};

std::unique_ptr<ITransformer> CreateKuwoDecryptionTransformer(const uint8_t *key)
{
    return std::make_unique<KuwoDecryptionTransformer>(key);
}

} // namespace parakeet_crypto::transformer
