#include "ncm_key_utils.h"

#include "parakeet-crypto/IStream.h"
#include "parakeet-crypto/ITransformer.h"
#include "parakeet-crypto/transformer/ncm.h"
#include "sized_block_reader.h"
#include "utils/endian_helper.h"
#include "utils/loop_iterator.h"
#include "utils/paged_reader.h"
#include "utils/xor_helper.h"

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

class NCMTransformer final : public ITransformer
{
  private:
    static constexpr size_t kHeaderPadding{2};
    static constexpr size_t kCoverPadding{9};

    std::array<uint8_t, kNCMContentKeySize> content_key_{};

    [[nodiscard]] std::optional<std::array<uint8_t, kNCMFinalKeyLen>> ReadContentKey(IReadSeekable *input)
    {
        std::array<uint8_t, sizeof(uint32_t) / sizeof(uint8_t)> buffer{};
        if (!input->ReadExact(buffer.data(), buffer.size()))
        {
            return {};
        }
        auto block_size = size_t{ReadLittleEndian<uint32_t>(buffer.data())};
        std::vector<uint8_t> key_buffer(block_size, 0);
        if (!input->ReadExact(key_buffer.data(), block_size))
        {
            return {};
        }
        return DecryptNCMAudioKey(key_buffer, content_key_);
    }

    [[nodiscard]] static bool SeekSizedBox(IReadSeekable *input)
    {
        std::array<uint8_t, sizeof(uint32_t) / sizeof(uint8_t)> buffer{};
        if (!input->ReadExact(buffer.data(), buffer.size()))
        {
            return false;
        }
        input->Seek(ReadLittleEndian<uint32_t>(buffer.data()), SeekDirection::SEEK_CURRENT_POSITION);
        return true;
    }

  public:
    NCMTransformer(const uint8_t *content_key) : ITransformer()
    {
        std::copy_n(content_key, content_key_.size(), content_key_.begin());
    }

    const char *GetName() override
    {
        return "NCM";
    }

    TransformResult Transform(IWriteable *output, IReadSeekable *input) override
    {
        constexpr static std::array<const uint8_t, 8> kHeader{'C', 'T', 'E', 'N', 'F', 'D', 'A', 'M'};

        std::array<uint8_t, kHeader.size()> file_header{};
        if (!input->ReadExact(file_header.data(), file_header.size()))
        {
            return TransformResult::ERROR_INSUFFICIENT_INPUT;
        }
        if (!std::equal(kHeader.begin(), kHeader.end(), file_header.begin()))
        {
            return TransformResult::ERROR_INVALID_FORMAT;
        }

        input->Seek(kHeaderPadding, SeekDirection::SEEK_CURRENT_POSITION);

        // Parse key
        auto tmp_key = ReadContentKey(input);
        if (!tmp_key)
        {
            return TransformResult::ERROR_INVALID_KEY;
        }
        auto audio_content_key = *tmp_key;

        // skip metadata
        if (!SeekSizedBox(input))
        {
            return TransformResult::ERROR_INVALID_FORMAT;
        }
        input->Seek(kCoverPadding, SeekDirection::SEEK_CURRENT_POSITION); // skip cover padding
        // skip cover
        if (!SeekSizedBox(input))
        {
            return TransformResult::ERROR_INVALID_FORMAT;
        }

        utils::LoopIterator key_iter{audio_content_key.data(), audio_content_key.size(), 0};
        auto decrypt_ok = utils::PagedReader{input}.ReadInPages([&](size_t /*offset*/, uint8_t *buffer, size_t n) {
            std::for_each_n(buffer, n, [&](auto &value) { value ^= key_iter.GetAndMove(); });
            return output->Write(buffer, n);
        });

        return decrypt_ok ? TransformResult::OK : TransformResult::ERROR_OTHER;
    }
};

std::unique_ptr<ITransformer> CreateNeteaseNCMDecryptionTransformer(const uint8_t *content_key)
{
    return std::make_unique<NCMTransformer>(content_key);
}

} // namespace parakeet_crypto::transformer
