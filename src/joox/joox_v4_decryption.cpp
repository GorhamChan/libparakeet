#include "joox/joox_const.h"
#include "parakeet-crypto/ITransformer.h"
#include "parakeet-crypto/transformer/joox.h"
#include "parakeet-crypto/utils/aes.h"
#include "parakeet-crypto/utils/hash/pbkdf2_hmac_sha1.h"
#include "parakeet-crypto/utils/hash/sha1.h"
#include "utils/endian_helper.h"
#include "utils/paged_reader.h"
#include "utils/pkcs7.hpp"

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
    static constexpr std::size_t kAESBlockSize = 0x10;
    static constexpr std::size_t kPlainBlockSize = 0x100000;                   // 1MiB
    static constexpr std::size_t kEncryptedBlockSize = kPlainBlockSize + 0x10; // padding (0x10, ...)

    std::array<uint8_t, utils::hash::kSHA1DigestSize> key_{};

    inline void SetupKey(JooxConfig &config)
    {
        utils::hash::pbkdf2_hmac_sha1(key_, config.install_uuid, config.salt, joox::kDeriveIteration);
    }

  public:
    JooxDecryptionV4Transformer(JooxConfig config)
    {
        SetupKey(config);
    }

    const char *GetName() override
    {
        return "JOOX (Dv4)";
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

        auto aes_decrypt = utils::aes::make_aes_128_ecb_decryptor(key_.data());
        bool io_ok{true};
        auto decrypt_ok = Reader{input}.WithPageSize(kEncryptedBlockSize, [&](size_t, uint8_t *buffer, size_t n) {
            // Decrypt content
            if (!aes_decrypt->Process(buffer, n))
            {
                return false; // buffer not in blocked size
            }

            size_t unpadded_len{0};
            if (utils::PKCS7_unpad<kAESBlockSize>(buffer, n, unpadded_len) != 0)
            {
                return false;
            }

            // Validation ok, resume.
            io_ok = output->Write(buffer, unpadded_len);
            return io_ok;
        });

        return decrypt_ok ? TransformResult::OK
               : io_ok    ? TransformResult::ERROR_INVALID_KEY
                          : TransformResult::ERROR_IO_OUTPUT_UNKNOWN;
    }
};

std::unique_ptr<ITransformer> CreateJooxDecryptionV4Transformer(JooxConfig config)
{
    return std::make_unique<JooxDecryptionV4Transformer>(std::move(config));
}

} // namespace parakeet_crypto::transformer
