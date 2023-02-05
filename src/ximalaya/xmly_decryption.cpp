#include "parakeet-crypto/ITransformer.h"
#include "parakeet-crypto/transformer/ximalaya.h"
#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <vector>

namespace parakeet_crypto::transformer
{

class XimalayaTransformer : public ITransformer
{
  private:
    std::array<uint8_t, kXimalayaScrambleKeyLen> scramble_key_{};
    std::vector<uint8_t> content_key_{};

  public:
    XimalayaTransformer(const uint8_t *scramble_key, const uint8_t *content_key, size_t content_key_len)
    {
        std::copy_n(scramble_key, scramble_key_.size(), scramble_key_.begin());
        content_key_.assign(content_key, content_key + content_key_len);
    }
    TransformResult Transform(uint8_t *output, size_t &output_len, const uint8_t *input, size_t input_len) override
    {
        return TransformResult::ERROR_NOT_IMPLEMENTED;
    }
};

std::unique_ptr<ITransformer> CreateXimalayaDecryptionTransformer(const uint8_t *scramble_key,
                                                                  const uint8_t *content_key, size_t content_key_len)
{
    return std::make_unique<XimalayaTransformer>(scramble_key, content_key, content_key_len);
}

} // namespace parakeet_crypto::transformer
