#include "kuwo_common.h"
#include "parakeet-crypto/transformer/kuwo.h"

#include "parakeet-crypto/ITransformer.h"

#include "transformer/kuwo/kuwo_common.h"
#include "utils/EndianHelper.h"
#include "utils/StringHelper.h"
#include "utils/XorHelper.h"

#include <cinttypes>
#include <cstdint>

#include <algorithm>
#include <array>
#include <cstring>
#include <memory>
#include <vector>

namespace parakeet_crypto::transformer
{

class KuwoEncryptionTransformer : public ITransformer
{
  private:
    enum class State
    {
        GENERATE_HEADER,
        CONTENT_ENCRYPTION,
    };

    State state_ = State::GENERATE_HEADER;
    size_t offset_ = 0;
    uint64_t resource_id_{};
    std::array<uint8_t, kKuwoDecryptionKeySize> key_{};

  public:
    KuwoEncryptionTransformer(const uint8_t *key, uint64_t resource_id) : ITransformer(), resource_id_(resource_id)
    {
        std::copy_n(key, kKuwoDecryptionKeySize, key_.begin());
        SetupKuwoDecryptionKey(resource_id, key_.begin(), key_.end());
    }

    TransformResult Transform(uint8_t *output, size_t &output_len, const uint8_t *input, size_t input_len) override
    {
        size_t bytes_written = 0;
        auto result = TransformResult::OK;
        while (input_len > 0 && result == TransformResult::OK)
        {
            switch (state_)
            {
            case State::GENERATE_HEADER:
                result = GenerateHeader(bytes_written, output, output_len);
                break;
            case State::CONTENT_ENCRYPTION:
                result = EncryptBuffer(bytes_written, output, output_len, input, input_len);
                break;
            }
        }

        output_len = bytes_written;
        return result;
    }

    TransformResult EncryptBuffer(size_t &bytes_written, uint8_t *&output, size_t &output_len, const uint8_t *&input,
                                  size_t &input_len)
    {
        if (input_len > output_len)
        {
            bytes_written += input_len;
            return TransformResult::ERROR_INSUFFICIENT_OUTPUT;
        }

        utils::XorBlockWithOffset(output, input, input_len, key_.data(), key_.size(), offset_);

        bytes_written += input_len;
        output += input_len;
        output_len -= input_len;
        input += input_len;
        input_len -= input_len;

        return TransformResult::OK;
    }

    TransformResult GenerateHeader(size_t &bytes_written, uint8_t *&output, size_t &output_len)
    {
        if (output_len < kFullKuwoHeaderLen)
        {
            bytes_written = kFullKuwoHeaderLen;
            return TransformResult::ERROR_INSUFFICIENT_OUTPUT;
        }

        KuwoHeader hdr{};
        std::copy(kKnownKuwoHeader2.begin(), kKnownKuwoHeader2.end(), &hdr.header[0]);
        hdr.resource_id = SwapHostToLittleEndian(resource_id_);

        std::memcpy(output, &hdr, sizeof(hdr));
        bytes_written += kFullKuwoHeaderLen;
        output_len -= kFullKuwoHeaderLen;
        output += kFullKuwoHeaderLen;

        state_ = State::CONTENT_ENCRYPTION;

        return TransformResult::OK;
    }
};
std::unique_ptr<ITransformer> CreateKuwoEncryptionTransformer(const uint8_t *key, uint64_t resource_id)
{
    return std::make_unique<KuwoEncryptionTransformer>(key, resource_id);
}

} // namespace parakeet_crypto::transformer
