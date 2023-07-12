#include "joox/joox_const.h"
#include "parakeet-crypto/ITransformer.h"
#include "parakeet-crypto/transformer/joox.h"
#include "parakeet-crypto/utils/aes.h"
#include "parakeet-crypto/utils/hash/pbkdf2_hmac_sha1.h"
#include "parakeet-crypto/utils/hash/sha1.h"
#include "utils/endian_helper.h"
#include "utils/paged_reader.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace parakeet_crypto::transformer
{

class JooxEncryptionV4Transformer final : public ITransformer
{
  private:
    static constexpr std::size_t kAESBlockSize = 0x10;
    static constexpr std::size_t kPlainBlockSize = 0x100000;                   // 1MiB
    static constexpr std::size_t kEncryptedBlockSize = kPlainBlockSize + 0x10; // padding (0x10, ...)

    std::array<uint8_t, utils::hash::kSHA1DigestSize> key_{};

    inline void SetupKey(JooxConfig &config)
    {
        utils::hash::pbkdf2_hmac_sha1(key_, config.install_uuid, config.salt, joox::kDeriveIteration);
    }

  public:
    JooxEncryptionV4Transformer(JooxConfig config)
    {
        SetupKey(config);
    }

    const char *GetName() override
    {
        return "JOOX (Ev4)";
    }

    TransformResult Transform(IWriteable *output, IReadSeekable *input) override
    {
        constexpr std::size_t kVer4HeaderSize = 12; /* 'E!04' + uint64_t_be(file size) */
        constexpr static std::array<uint8_t, 4> kMagicHeader{'E', '!', '0', '4'};

        std::array<uint8_t, kVer4HeaderSize> header{};
        std::copy(kMagicHeader.begin(), kMagicHeader.end(), header.begin());
        WriteBigEndian(&header.at(4), uint64_t{input->GetSize()});
        if (!output->Write(header.data(), header.size()))
        {
            return TransformResult::ERROR_IO_OUTPUT_UNKNOWN;
        }

        using Reader = utils::PagedReader;

        auto aes_encrypt = aes::make_aes_128_ecb_encryptor(key_.data());
        std::array<uint8_t, kAESBlockSize> padding_block{};
        auto decrypt_ok = Reader{input}.WithPageSize(kPlainBlockSize, [&](size_t, uint8_t *buffer, size_t n) {
            auto exceed_bytes = n % kAESBlockSize;
            auto padding_byte = static_cast<uint8_t>(kAESBlockSize - exceed_bytes);
            auto actual_len = n - exceed_bytes;

            if (!aes_encrypt->process(buffer, actual_len))
            {
                return false; // size mismatch
            }

            if (!output->Write(buffer, actual_len))
            {
                return false; // i/o error
            }

            // Write padding:
            std::fill(padding_block.begin(), padding_block.end(), padding_byte);
            std::copy_n(buffer + actual_len, exceed_bytes, padding_block.begin());
            if (!aes_encrypt->process(padding_block))
            {
                return false; // padding_block is in the wrong size?
            }

            return output->Write(padding_block.data(), padding_block.size());
        });

        return decrypt_ok ? TransformResult::OK : TransformResult::ERROR_IO_OUTPUT_UNKNOWN;
    }
};

std::unique_ptr<ITransformer> CreateJooxEncryptionV4Transformer(JooxConfig config)
{
    return std::make_unique<JooxEncryptionV4Transformer>(std::move(config));
}

} // namespace parakeet_crypto::transformer
