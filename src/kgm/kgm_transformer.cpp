#include "kgm/kgm_crypto.h"
#include "kgm/kgm_header.h"
#include "parakeet-crypto/IStream.h"
#include "parakeet-crypto/ITransformer.h"
#include "parakeet-crypto/transformer/kgm.h"
#include "utils/endian_helper.h"
#include "utils/paged_reader.h"
#include "utils/xor_helper.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>

namespace parakeet_crypto::transformer
{

class KGMDecryptionTransformer final : public ITransformer
{
  private:
    KGMConfig config_{};

  public:
    KGMDecryptionTransformer(KGMConfig config) : config_(std::move(config))
    {
    }

    /**
     * @brief Transform a given block of data.
     *
     * @param output Output buffer.
     * @param output_len Output size. Use `0` to get the output size.
     * @param input Input buffer.
     * @param input_len Input buffer size.
     * @return TransformResult
     */
    TransformResult Transform(IWriteable *output, IReadSeekable *input) override
    {
        kgm::FileHeader header{};
        {
            auto header_opt = kgm::FileHeaderFromStream(input);
            if (!header_opt)
            {
                return TransformResult::ERROR_INSUFFICIENT_INPUT;
            }
            header = *header_opt;
        }

        auto decryptor = kgm::CreateKGMDecryptionCrypto(header, config_);
        if (!decryptor)
        {
            return TransformResult::ERROR_INVALID_FORMAT;
        }

        const auto audio_offset = header.offset_to_data;
        input->Seek(audio_offset, SeekDirection::SEEK_FILE_BEGIN);

        auto decrypt_ok = utils::PagedReader{input}.ReadInPages([&](size_t offset, uint8_t *buffer, size_t n) {
            decryptor->Decrypt(offset - audio_offset, buffer, n);
            return output->Write(buffer, n);
        });

        return decrypt_ok ? TransformResult::OK : TransformResult::ERROR_OTHER;
    }
};

std::unique_ptr<ITransformer> CreateKGMDecryptionTransformer(KGMConfig config)
{
    return std::make_unique<KGMDecryptionTransformer>(std::move(config));
}

} // namespace parakeet_crypto::transformer
