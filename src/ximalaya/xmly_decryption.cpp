#include "parakeet-crypto/ITransformer.h"
#include "parakeet-crypto/transformer/ximalaya.h"
#include "utils/loop_iterator.h"
#include "utils/paged_reader.h"
#include "utils/xor_helper.h"
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
    std::vector<uint8_t> content_key_{};

  public:
    XimalayaTransformer(const uint16_t *scramble_key, const uint8_t *content_key, size_t content_key_len)
    {
        std::copy_n(scramble_key, scramble_key_.size(), scramble_key_.begin());
        content_key_.assign(content_key, content_key + content_key_len);
    }

    TransformResult Transform(IWriteable *output, IReadSeekable *input) override
    {
        std::array<uint8_t, kXimalayaScrambleKeyLen> header_src{};
        if (!input->ReadExact(header_src.data(), header_src.size()))
        {
            return TransformResult::ERROR_INVALID_FORMAT;
        }

        std::array<uint8_t, kXimalayaScrambleKeyLen> header_dst{};
        for (int i = 0; i < kXimalayaScrambleKeyLen; i++)
        {
            header_dst[i] = header_src[scramble_key_[i]];
        }

        utils::LoopIterator key_iter{content_key_.data(), content_key_.size(), 0};
        std::for_each(header_dst.begin(), header_dst.end(), [&](auto &value) { value ^= key_iter.GetAndMove(); });

        output->Write(header_dst.data(), header_dst.size());

        // Transparent copy.
        auto decrypt_ok = utils::PagedReader{input}.ReadInPages([&](size_t /*offset*/, uint8_t *buffer, size_t n) {
            output->Write(buffer, n);
            return true;
        });

        return TransformResult::OK;
    }
};

std::unique_ptr<ITransformer> CreateXimalayaDecryptionTransformer(const uint16_t *scramble_key,
                                                                  const uint8_t *content_key, size_t content_key_len)
{
    return std::make_unique<XimalayaTransformer>(scramble_key, content_key, content_key_len);
}

} // namespace parakeet_crypto::transformer
