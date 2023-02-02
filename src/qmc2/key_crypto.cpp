#include "key_v1.h"
#include "key_v2.h"

#include "parakeet-crypto/qmc2/key_crypto.h"
#include "qmc2/key_v2.h"
#include "utils/base64.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace parakeet_crypto::qmc2
{

class KeyCryptoImpl : public IKeyCrypto
{
  private:
    static constexpr size_t kTeaKeySize = 16;

    std::array<uint8_t, kTeaKeySize> enc_v2_key_1_{};
    std::array<uint8_t, kTeaKeySize> enc_v2_key_2_{};

  public:
    KeyCryptoImpl(const uint8_t *enc_v2_key_1, const uint8_t *enc_v2_key_2)
    {
        std::copy_n(enc_v2_key_1, kTeaKeySize, enc_v2_key_1_.begin());
        std::copy_n(enc_v2_key_2, kTeaKeySize, enc_v2_key_2_.begin());
    }
    ~KeyCryptoImpl() override = default;

    inline KeyEncryptionV2 GetEncV2()
    {
        return {enc_v2_key_1_.data(), enc_v2_key_2_.data()};
    }

    inline KeyEncryptionV1 GetEncV1() // NOLINT(*-member-functions-to-static)
    {
        return {};
    }

    std::vector<uint8_t> Decrypt(const uint8_t *key_cipher, size_t len) override
    {
        auto key = utils::Base64Decode(key_cipher, len);
        if (KeyEncryptionV2::IsEncV2(key.data()))
        {
            auto decrypted_key = GetEncV2().Decrypt(key);
            if (!decrypted_key.has_value())
            {
                return {};
            }
            key = decrypted_key.value();
        }

        if (auto decrypted_key = GetEncV1().Decrypt(key))
        {
            return decrypted_key.value();
        }

        return {};
    }

    std::vector<uint8_t> Encrypt(const uint8_t *key, size_t len, KeyVersion version) override
    {
        std::vector<uint8_t> result(key, key + len);
        result = GetEncV1().Encrypt(result);
        if (version == KeyVersion::VERSION_2)
        {
            result = GetEncV2().Encrypt(result);
        }
        result = utils::Base64Encode(result);
        return result;
    }
};

std::unique_ptr<IKeyCrypto> CreateKeyCrypto(const uint8_t *enc_v2_key_1, const uint8_t *enc_v2_key_2)
{
    return std::make_unique<KeyCryptoImpl>(enc_v2_key_1, enc_v2_key_2);
}

} // namespace parakeet_crypto::qmc2
