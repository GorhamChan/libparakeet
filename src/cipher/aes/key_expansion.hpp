#include "parakeet-crypto/cipher/aes/aes.h"

#include "helper.hpp"

#include <algorithm>
#include <array>
#include <cstdint>

namespace parakeet_crypto::cipher::aes
{

// Implementation based on tiny-AES-c: https://github.com/kokke/tiny-AES-c
// tiny-AES-c License: unlicense (public domain; http://unlicense.org/)

template <BLOCK_SIZE kBlockSize, CRYPTO_MODE mode> void AES<kBlockSize, mode>::SetKey(const uint8_t *key)
{
    // The first round key is the key itself.
    uint8_t *p_key_bytes = key_.data();
    // NOLINTNEXTLINE(*-reinterpret-cast)
    auto *p_key_words = reinterpret_cast<uint32_t *>(p_key_bytes);

    std::copy_n(key, CONFIG::kKeyBlockSize, p_key_bytes);

    uint32_t temp{};
    for (int i = CONFIG::kKeyWordSize; i < ((CONFIG::kKeyRounds + 1) * 4); i++)
    {
        temp = p_key_words[i - 1];

        if (i % CONFIG::kKeyWordSize == 0)
        {
            temp = RotWord(temp);
            temp = SubWord(temp);
            temp = ApplyRoundConstant(temp, i / CONFIG::kKeyWordSize);
        }

        if constexpr (CONFIG::kIs256)
        {
            if (i % CONFIG::kKeyWordSize == 4)
            {
                temp = SubWord(temp);
            }
        }

        p_key_words[i] = p_key_words[i - CONFIG::kKeyWordSize] ^ temp;
    }
}

template void AES<BLOCK_SIZE::AES_128, CRYPTO_MODE::Encrypt>::SetKey(const uint8_t *key);
template void AES<BLOCK_SIZE::AES_128, CRYPTO_MODE::Decrypt>::SetKey(const uint8_t *key);

template void AES<BLOCK_SIZE::AES_192, CRYPTO_MODE::Encrypt>::SetKey(const uint8_t *key);
template void AES<BLOCK_SIZE::AES_192, CRYPTO_MODE::Decrypt>::SetKey(const uint8_t *key);

template void AES<BLOCK_SIZE::AES_256, CRYPTO_MODE::Encrypt>::SetKey(const uint8_t *key);
template void AES<BLOCK_SIZE::AES_256, CRYPTO_MODE::Decrypt>::SetKey(const uint8_t *key);

}; // namespace parakeet_crypto::cipher::aes
