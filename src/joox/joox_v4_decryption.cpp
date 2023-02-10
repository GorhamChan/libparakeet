#include "parakeet-crypto/ITransformer.h"
#include "parakeet-crypto/transformer/joox.h"
#include "utils/endian_helper.h"
#include "utils/paged_reader.h"

#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>

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

class JooxDecryptionV4Transformer final : public ITransformer
{
  private:
    using AES_ECB = CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption;
    static constexpr std::size_t kAESBlockSize = 0x10;
    static constexpr std::size_t kPlainBlockSize = 0x100000;                   // 1MiB
    static constexpr std::size_t kEncryptedBlockSize = kPlainBlockSize + 0x10; // padding (0x10, ...)

    std::array<uint8_t, CryptoPP::SHA1::DIGESTSIZE> key_{};

    inline void SetupKey(JooxConfig &config)
    {
        constexpr size_t kDeriveIteration = 1000;
        CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA1> pbkdf{};
        pbkdf.DeriveKey(
            key_.data(), key_.size(), 0 /* unused */,
            reinterpret_cast<const uint8_t *>(config.install_uuid.c_str()), // NOLINT(*-type-reinterpret-cast)
            config.install_uuid.size(), config.salt.data(), config.salt.size(), kDeriveIteration, 0);
    }

  public:
    JooxDecryptionV4Transformer(JooxConfig config)
    {
        SetupKey(config);
    }

    TransformResult Transform(IWriteable *output, IReadSeekable *input) override
    {
        constexpr std::size_t kVer4HeaderSize = 12; /* 'E!04' + uint64_t_be(file size) */
        constexpr static std::array<uint8_t, 4> kMagicHeader{'E', '!', '0', '4'};

        std::array<uint8_t, kVer4HeaderSize> header{};
        if (!input->ReadExact(header.data(), header.size()))
        {
            return TransformResult::ERROR_INSUFFICIENT_INPUT;
        }
        if (!std::equal(kMagicHeader.begin(), kMagicHeader.end(), header.begin()))
        {
            return TransformResult::ERROR_INVALID_FORMAT;
        }

        // auto actual_size = ReadBigEndian<uint64_t>(&header.at(4)); // is this used?

        using Reader = utils::PagedReader;

        AES_ECB aes{key_.data(), kAESBlockSize};
        auto decrypt_ok = Reader{input}.WithPageSize(kEncryptedBlockSize, [&](size_t, uint8_t *buffer, size_t n) {
            if (n < kAESBlockSize || (n % kAESBlockSize != 0))
            {
                return false;
            }

            // Decrypt content
            aes.ProcessData(buffer, buffer, n);

            // Locate padding bytes
            const auto *p_padding_block = buffer + n - kAESBlockSize;
            uint8_t trim = p_padding_block[kAESBlockSize - 1];
            if (trim == 0 || trim > kAESBlockSize)
            {
                return false; // invalid pkcs5 padding
            }

            // Validate pkcs5 padding
            uint8_t zero_sum = 0;
            for (std::size_t i = kAESBlockSize - trim; i < kAESBlockSize; i++)
            {
                zero_sum |= p_padding_block[i] ^ trim;
            }

            if (zero_sum != 0)
            {
                return false; // pkcs5 padding validation failed
            }

            // Validation ok, resume.
            output->Write(buffer, n - size_t{trim});
            return true;
        });

        return decrypt_ok ? TransformResult::OK : TransformResult::ERROR_INVALID_KEY;
    }
};

std::unique_ptr<ITransformer> CreateJooxDecryptionV4Transformer(JooxConfig config)
{
    return std::make_unique<JooxDecryptionV4Transformer>(std::move(config));
}

} // namespace parakeet_crypto::transformer
