#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <vector>

namespace parakeet_crypto::utils::aes
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

template <BLOCK_SIZE tplBlockSize> class AESConfig
{
  public:
    static constexpr size_t kBlockSize = 16;
    static constexpr size_t kKeyBlockSize = static_cast<size_t>(tplBlockSize);
    static constexpr size_t kKeySize = kKeyBlockSize;
    static constexpr size_t kKeyWordSize = kKeyBlockSize / 4;
    static constexpr size_t kKeyRounds = GetKeyRounds(tplBlockSize);
    static constexpr size_t kKeyExpansionSize = GetKeyExpansionSize(tplBlockSize);

    static constexpr bool kIs128 = (tplBlockSize == BLOCK_SIZE::AES_128);
    static constexpr bool kIs192 = (tplBlockSize == BLOCK_SIZE::AES_192);
    static constexpr bool kIs256 = (tplBlockSize == BLOCK_SIZE::AES_256);
};

}; // namespace detail

template <BLOCK_SIZE tplBlockSize, CRYPTO_MODE Mode> class AES
{
  public:
    using CONFIG = detail::AESConfig<tplBlockSize>;
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

    ~AES()
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

    void ProcessBlock(uint8_t *buffer);

    bool Process(uint8_t *buffer, size_t n)
    {
        if (n % CONFIG::kBlockSize != 0)
        {
            return false;
        }

        auto *p_end = buffer + n;
        while (buffer < p_end)
        {
            ProcessBlock(buffer);
            buffer += CONFIG::kBlockSize;
        }
        return true;
    }

    template <typename T> inline bool Process(T &buffer)
    {
        return Process(buffer.data(), buffer.size());
    }

  private:
    std::array<uint8_t, CONFIG::kKeyExpansionSize> key_{};
};

inline std::unique_ptr<AES<BLOCK_SIZE::AES_128, CRYPTO_MODE::Decrypt>> make_aes_128_ecb_decryptor(const uint8_t *key)
{
    return std::make_unique<AES<BLOCK_SIZE::AES_128, CRYPTO_MODE::Decrypt>>(key);
}

inline std::unique_ptr<AES<BLOCK_SIZE::AES_128, CRYPTO_MODE::Encrypt>> make_aes_128_ecb_encryptor(const uint8_t *key)
{
    return std::make_unique<AES<BLOCK_SIZE::AES_128, CRYPTO_MODE::Encrypt>>(key);
}

}; // namespace parakeet_crypto::utils::aes
