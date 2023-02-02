#include "parakeet-crypto/ITransformer.h"
#include "parakeet-crypto/transformer/qmc.h"
#include "qmc1_key_utils.h"
#include "transformer/qmc/qmc1_key_utils.h"
#include "utils/XorHelper.h"

#include <algorithm>
#include <array>
#include <cstdint>

namespace parakeet_crypto::transformer
{

constexpr size_t kQMC1KeySize = 128;
constexpr size_t kCipherPageSize = 0x7fff;

template <uint32_t OFFSET> class QMC1StaticDecryptionTransformer : public ITransformer
{
  private:
    size_t offset_ = 0;
    std::array<uint8_t, kQMC1KeySize> key_{};

  public:
    QMC1StaticDecryptionTransformer(const uint8_t *key) : ITransformer()
    {
        std::copy_n(key, key_.size(), key_.begin());
    }

    TransformResult Transform(uint8_t *output, size_t &output_len, const uint8_t *input, size_t input_len) override
    {
        if (output_len < input_len)
        {
            output_len = input_len;
            return TransformResult::ERROR_INSUFFICIENT_OUTPUT;
        }
        output_len = input_len;

        utils::XorBlockFromOffset(output, input, input_len, kCipherPageSize, key_.data(), key_.size(), offset_);

        // Off-by-1 fix at the first page.
        if (offset_ < kCipherPageSize && kCipherPageSize < input_len + offset_)
        {
            auto boundary_index = kCipherPageSize - offset_;
            output[boundary_index] = input[boundary_index] ^ key_[kCipherPageSize % key_.size()];
        }

        offset_ += input_len;

        return TransformResult::OK;
    }
};

std::unique_ptr<ITransformer> CreateQMC1StaticDecryptionTransformer(const uint8_t *key, size_t key_len)
{
    // TODO: Downgrade / upgrade key with size 128 or 256.
    return std::make_unique<QMC1StaticDecryptionTransformer<qmc1::kIndexOffset>>(key);
}

} // namespace parakeet_crypto::transformer
