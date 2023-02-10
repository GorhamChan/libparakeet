#include "kgm_crypto.h"
#include "utils/loop_iterator.h"
#include "utils/md5.h"
#include <algorithm>
#include <cstdint>
#include <memory>

namespace parakeet_crypto::kgm
{

class KGMCryptoType3 final : public IKGMCrypto
{
  private:
    // NOLINTBEGIN(*-magic-numbers)
    std::array<uint8_t, 16> slot_key_{};
    std::array<uint8_t, 17> file_key_{};
    // NOLINTEND(*-magic-numbers)

    static inline std::array<uint8_t, utils::MD5_DIGEST_SIZE> hash_type3(const uint8_t *data, size_t len)
    {
        constexpr size_t kMD5DigestSize = utils::MD5_DIGEST_SIZE;
        constexpr size_t kDigestMidIndex = kMD5DigestSize / 2;
        auto digest = utils::md5(data, len);

        // Reverse 2-bytes at a time.
        for (int i = 0; i < utils::MD5_DIGEST_SIZE / 2; i += 2)
        {
            std::swap(digest[i + 0], digest[utils::MD5_DIGEST_SIZE - 2 - i]);
            std::swap(digest[i + 1], digest[utils::MD5_DIGEST_SIZE - 1 - i]);
        }
        return digest;
    }

  public:
    bool Configure(const transformer::KGMConfig & /*config*/, const std::vector<uint8_t> &slot_key,
                   const FileHeader &header) override
    {
        static_assert(sizeof(header.file_key) == 16); // NOLINT(*-magic-numbers)

        slot_key_ = hash_type3(slot_key.data(), slot_key.size());
        auto file_key = hash_type3(&header.file_key[0], sizeof(header.file_key));
        std::copy(file_key.cbegin(), file_key.cend(), file_key_.begin());
        file_key_.back() = 'k';

        return true;
    }

    template <bool IS_ENCRYPT> void EncryptDecrypt(uint64_t offset, uint8_t *buffer, size_t len)
    {
        utils::LoopIterator slot_key{slot_key_.data(), slot_key_.size(), offset};
        utils::LoopIterator file_key{file_key_.data(), file_key_.size(), offset};

        auto *end = buffer + len;
        for (auto *it = buffer; it < end; it++)
        {
            uint8_t offset_key = xor_u32_bytes(static_cast<uint32_t>(offset));

            auto v = *it; // NOLINT(readability-identifier-length)
            if constexpr (IS_ENCRYPT)
            {
                v ^= offset_key;
                v ^= slot_key.Get();
                v ^= v << 4;
                v ^= file_key.Get();
            }
            else
            {
                v ^= file_key.Get();
                v ^= v << 4;
                v ^= slot_key.Get();
                v ^= offset_key;
            }
            *it = v;

            offset++;
            slot_key.Next();
            file_key.Next();
        }
    }

    void Encrypt(uint64_t offset, uint8_t *buffer, size_t len) override
    {
        EncryptDecrypt<true>(offset, buffer, len);
    }

    void Decrypt(uint64_t offset, uint8_t *buffer, size_t len) override
    {
        EncryptDecrypt<false>(offset, buffer, len);
    }
};

std::unique_ptr<IKGMCrypto> CreateKGMCryptoType3()
{
    return std::make_unique<KGMCryptoType3>();
}

} // namespace parakeet_crypto::kgm
