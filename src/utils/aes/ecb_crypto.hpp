#include "helper.hpp"

#include "parakeet-crypto/utils/aes.h"

namespace parakeet_crypto::utils::aes
{

template <BLOCK_SIZE kBlockSize, typename T> inline void EncryptBlock(const T &round_keys, uint8_t *buffer)
{
    using namespace detail;
    using CONFIG = AESConfig<kBlockSize>;

    AddRoundKey(buffer, round_keys, 0);
    for (int i = 1; i < CONFIG::kKeyRounds; i++)
    {
        SubBytes(buffer);
        ShiftRows(buffer);
        MixColumns(buffer);
        AddRoundKey(buffer, round_keys, i);
    }

    SubBytes(buffer);
    ShiftRows(buffer);
    AddRoundKey(buffer, round_keys, CONFIG::kKeyRounds);
}

template <BLOCK_SIZE kBlockSize, typename T> inline void DecryptBlock(const T &round_keys, uint8_t *buffer)
{
    using namespace detail;
    using CONFIG = AESConfig<kBlockSize>;

    AddRoundKey(buffer, round_keys, CONFIG::kKeyRounds);
    for (int i = CONFIG::kKeyRounds - 1; i > 0; i--)
    {
        InvShiftRows(buffer);
        InvSubBytes(buffer);
        AddRoundKey(buffer, round_keys, i);
        InvMixColumns(buffer);
    }

    InvShiftRows(buffer);
    InvSubBytes(buffer);
    AddRoundKey(buffer, round_keys, 0);
}

template <BLOCK_SIZE kBlockSize, CRYPTO_MODE kMode> void AES<kBlockSize, kMode>::ProcessBlock(uint8_t *buffer)
{
    if constexpr (kMode == CRYPTO_MODE::Encrypt)
    {
        EncryptBlock<kBlockSize>(key_, buffer);
    }
    else
    {
        DecryptBlock<kBlockSize>(key_, buffer);
    }
}

// Specializations

template void AES<BLOCK_SIZE::AES_128, CRYPTO_MODE::Encrypt>::ProcessBlock(uint8_t *buffer);
template void AES<BLOCK_SIZE::AES_192, CRYPTO_MODE::Encrypt>::ProcessBlock(uint8_t *buffer);
template void AES<BLOCK_SIZE::AES_256, CRYPTO_MODE::Encrypt>::ProcessBlock(uint8_t *buffer);

template void AES<BLOCK_SIZE::AES_128, CRYPTO_MODE::Decrypt>::ProcessBlock(uint8_t *buffer);
template void AES<BLOCK_SIZE::AES_192, CRYPTO_MODE::Decrypt>::ProcessBlock(uint8_t *buffer);
template void AES<BLOCK_SIZE::AES_256, CRYPTO_MODE::Decrypt>::ProcessBlock(uint8_t *buffer);

} // namespace parakeet_crypto::utils::aes
