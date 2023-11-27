#pragma once

#include "../cipher_block.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <vector>

namespace parakeet_crypto::cipher::aes
{

enum class BLOCK_SIZE : size_t
{
    AES_128 = 128 / 8,
    AES_192 = 192 / 8,
    AES_256 = 256 / 8
};

enum class CRYPTO_MODE : int
{
    Decrypt = 0,
    Encrypt = 1,
};

namespace detail
{

constexpr size_t kKeyRounds_128 = 10;
constexpr size_t kKeyRounds_192 = 12;
constexpr size_t kKeyRounds_256 = 14;

constexpr size_t kKeyExpansionSize_128 = 176;
constexpr size_t kKeyExpansionSize_192 = 208;
constexpr size_t kKeyExpansionSize_256 = 240;

constexpr inline size_t GetKeyRounds(BLOCK_SIZE block_size)
{
    switch (block_size)
    {
    case BLOCK_SIZE::AES_128:
        return kKeyRounds_128;
    case BLOCK_SIZE::AES_192:
        return kKeyRounds_192;
    case BLOCK_SIZE::AES_256:
        return kKeyRounds_256;
    default:
        throw std::logic_error("Invalid AES block size");
    }
}

constexpr inline size_t GetKeyExpansionSize(BLOCK_SIZE block_size)
{
    return (1 + GetKeyRounds(block_size)) * static_cast<size_t>(block_size);
}

template <BLOCK_SIZE kKeySizeInBytes> class AESConfig
{
  public:
    /**
     * Process block size
     * This should always be 16, regardless of the key block size
     */
    static constexpr size_t kBlockSize = 16;
    static constexpr size_t kKeyBlockSize = static_cast<size_t>(kKeySizeInBytes);
    static constexpr size_t kKeySize = kKeyBlockSize;
    static constexpr size_t kKeyWordSize = kKeyBlockSize / 4;
    static constexpr size_t kKeyRounds = GetKeyRounds(kKeySizeInBytes);
    static constexpr size_t kKeyExpansionSize = GetKeyExpansionSize(kKeySizeInBytes);

    static constexpr bool kIs128 = (kKeySizeInBytes == BLOCK_SIZE::AES_128);
    static constexpr bool kIs192 = (kKeySizeInBytes == BLOCK_SIZE::AES_192);
    static constexpr bool kIs256 = (kKeySizeInBytes == BLOCK_SIZE::AES_256);
};

}; // namespace detail

template <BLOCK_SIZE kKeySizeInBytes, CRYPTO_MODE Mode>
class AES : public BlockCipher<detail::AESConfig<kKeySizeInBytes>::kBlockSize>
{
  public:
    using CONFIG = detail::AESConfig<kKeySizeInBytes>;

  private:
    std::array<uint8_t, CONFIG::kBlockSize> buffer_{};
    size_t buffer_idx_{0};

  public:
    AES() = default;
    inline AES(const uint8_t *key)
    {
        SetKey(key);
    }
    inline AES(const std::array<uint8_t, CONFIG::kKeySize> &key)
    {
        SetKey(key);
    }
    AES(const AES &) = delete;
    AES(AES &&) = delete;
    AES &operator=(const AES &) = delete;
    AES &operator=(AES &&) = delete;

    ~AES() override
    {
        std::fill(key_.begin(), key_.end(), 0);
    };

    inline std::array<uint8_t, CONFIG::kKeyExpansionSize> GetRoundKey()
    {
        std::array<uint8_t, CONFIG::kKeyExpansionSize> result(key_);
        return result;
    }

    void SetKey(const uint8_t *key);
    inline void SetKey(const std::array<uint8_t, CONFIG::kKeySize> &key)
    {
        SetKey(key.data());
    }

    CipherErrorCode TransformBlock(uint8_t *buffer) override;

  private:
    std::array<uint8_t, CONFIG::kKeyExpansionSize> key_{};
};

using AES128Dec = AES<BLOCK_SIZE::AES_128, CRYPTO_MODE::Decrypt>;
using AES192Dec = AES<BLOCK_SIZE::AES_192, CRYPTO_MODE::Decrypt>;
using AES256Dec = AES<BLOCK_SIZE::AES_256, CRYPTO_MODE::Decrypt>;

using AES128Enc = AES<BLOCK_SIZE::AES_128, CRYPTO_MODE::Encrypt>;
using AES192Enc = AES<BLOCK_SIZE::AES_192, CRYPTO_MODE::Encrypt>;
using AES256Enc = AES<BLOCK_SIZE::AES_256, CRYPTO_MODE::Encrypt>;

}; // namespace parakeet_crypto::cipher::aes
