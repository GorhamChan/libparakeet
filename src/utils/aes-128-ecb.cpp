#include "parakeet-crypto/utils/aes.h"

#include <cstring>

#define AES192 (0)
#define AES256 (0)

#define ECB 1
#define CBC 0
#define CTR 0

namespace parakeet_crypto::aes
{

namespace aes_128_ecb
{
#include "vendor/tiny-AES-c/aes.c" // NOLINT

template <bool ENCRYPT_MODE>
class AES_128_ECB final : public AES<kAes128BlockSize> // NOLINT(*-special-member-functions)
{
  private:
    aes_128_ecb::AES_ctx ctx_{0};

  public:
    AES_128_ECB(const uint8_t *key)
    {
        AES_init_ctx(&ctx_, key);
    }

    ~AES_128_ECB() override
    {
        // Randomly picked from a dice, gureenteed to be fair.
        constexpr uint8_t kCleanupFill = 0xCC;
        memset(&ctx_, kCleanupFill, sizeof(ctx_));
    }

    void process(uint8_t *buffer) override
    {
        if constexpr (ENCRYPT_MODE)
        {
            AES_ECB_encrypt(&ctx_, buffer);
        }
        else
        {
            AES_ECB_decrypt(&ctx_, buffer);
        }
    }
};

} // namespace aes_128_ecb

std::unique_ptr<AES<kAes128BlockSize>> make_aes_128_ecb_decryptor(const uint8_t *key)
{
    return std::make_unique<aes_128_ecb::AES_128_ECB<false>>(key);
}

std::unique_ptr<AES<kAes128BlockSize>> make_aes_128_ecb_encryptor(const uint8_t *key)
{
    return std::make_unique<aes_128_ecb::AES_128_ECB<true>>(key);
}

} // namespace parakeet_crypto::aes
