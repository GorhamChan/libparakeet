#include "parakeet-crypto/ITransformer.h"
#include "parakeet-crypto/transformer/ximalaya.h"
#include "utils/XorHelper.h"
#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace parakeet_crypto::transformer
{

class XimalayaTransformer : public ITransformer
{
  private:
    size_t offset_{};
    std::array<uint16_t, kXimalayaScrambleKeyLen> scramble_key_{};
    std::array<uint8_t, kXimalayaScrambleKeyLen> scramble_header_{};
    std::vector<uint8_t> content_key_{};

    void HandleHeaderDecryption(size_t &bytes_written, uint8_t *&output, size_t &output_len, const uint8_t *&input,
                                size_t &input_len)
    {
        auto header_process_n = std::min(kXimalayaScrambleKeyLen - offset_, input_len);
        std::copy_n(input, header_process_n, scramble_header_.begin() + offset_);

        input += header_process_n;
        input_len -= header_process_n;
        offset_ += header_process_n;

        if (offset_ == kXimalayaScrambleKeyLen)
        {
            auto *p_output = output;
            for (auto it = scramble_key_.begin(); it < scramble_key_.end(); it++) // NOLINT (readability-qualified-auto)
            {
                *output++ = scramble_header_[*it];
            }
            utils::XorFromOffset(p_output, kXimalayaScrambleKeyLen, content_key_.data(), content_key_.size(), 0);

            bytes_written += kXimalayaScrambleKeyLen;
            output_len -= kXimalayaScrambleKeyLen;
        }
    }

    [[nodiscard]] size_t GetMinimumRequiredLen(size_t input_len) const
    {
        if (offset_ > kXimalayaScrambleKeyLen)
        {
            return input_len;
        }

        return offset_ + input_len;
    }

  public:
    XimalayaTransformer(const uint16_t *scramble_key, const uint8_t *content_key, size_t content_key_len)
    {
        std::copy_n(scramble_key, scramble_key_.size(), scramble_key_.begin());
        content_key_.assign(content_key, content_key + content_key_len);
    }

    TransformResult Transform(uint8_t *output, size_t &output_len, const uint8_t *input, size_t input_len) override
    {
        auto required_len = GetMinimumRequiredLen(input_len);
        if (output_len < required_len)
        {
            output_len = required_len;
            return TransformResult::ERROR_INSUFFICIENT_OUTPUT;
        }

        size_t bytes_written{0};
        if (offset_ < kXimalayaScrambleKeyLen)
        {
            HandleHeaderDecryption(bytes_written, output, output_len, input, input_len);
        }

        // Transparent copy.
        if (input_len > 0)
        {
            std::copy_n(input, input_len, output);
            bytes_written += input_len;
        }

        output_len = bytes_written;
        return TransformResult::OK;
    }
};

std::unique_ptr<ITransformer> CreateXimalayaDecryptionTransformer(const uint16_t *scramble_key,
                                                                  const uint8_t *content_key, size_t content_key_len)
{
    return std::make_unique<XimalayaTransformer>(scramble_key, content_key, content_key_len);
}

} // namespace parakeet_crypto::transformer
