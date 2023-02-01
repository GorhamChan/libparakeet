#include "parakeet-crypto/decryptor/qmc/QMCLoader.h"

#include "utils/EndianHelper.h"
#include "utils/StringHelper.h"
#include "utils/XorHelper.h"

#include <cassert>

#include <algorithm>
#include <array>
#include <ranges>
#include <vector>

namespace parakeet_crypto::decryptor
{

// Private implementation

namespace tencent::detail
{

/**
 * @brief QMCv1 Encryption type.
 */
enum class QMCv1Type
{
    /**
     * @brief
     * Used by WeYun, old QQ Music client (with extension e.g. `qmcflac`)
     * Old cipher with static keys.
     */
    kStaticCipher = 0,

    /**
     * @brief
     * Used by QQ Music client (with extension e.g. `mflac`).
     * Same cipher but with a different key for each file.
     * Key derivation parameter is different than {@link kStaticCipher}
     *
     * Do _not_ feed the file footer to this crypto.
     */
    kMapCipher,
};

constexpr std::size_t kStaticCipherPageSize = 0x7fff;
constexpr std::size_t kStaticCipherFirstPageSize = kStaticCipherPageSize + 1;

template <QMCv1Type QMC1_TYPE> class QMCv1Decryptor : public StreamDecryptor
{
  private:
    std::vector<uint8_t> key_;
    std::string name_;
    std::array<uint8_t, kStaticCipherFirstPageSize> key_cache_;

  public:
    explicit QMCv1Decryptor(QMCv1KeyInput key)
    {
        if constexpr (QMC1_TYPE == QMCv1Type::kStaticCipher)
        {
            name_ = "QMCv1(static)";
            SetKey(key);
        }
        else if constexpr (QMC1_TYPE == QMCv1Type::kMapCipher)
        {
            name_ = "QMCv1(map)";
            std::vector<uint8_t> key_transformed(key.begin(), key.end());

            uint8_t i = 4;
            std::ranges::for_each(key_transformed, [&i](auto &v) {
                uint8_t shift = i & 0b0111;
                v = static_cast<uint8_t>((v << shift) | (v >> shift));
                i++;
            });
            SetKey(key_transformed);
        }
        else
        {
            assert(("unsupported QMC1_TYPE", 0));
        }
    }

    std::string GetName() const override
    {
        return name_;
    }

    bool Write(const uint8_t *in, std::size_t len) override
    {
        if (InErrorState())
            return false;

        auto p_out = ExpandOutputBuffer(len);

        if (offset_ < kStaticCipherFirstPageSize)
        {
            std::size_t process_size = std::min(kStaticCipherFirstPageSize - offset_, len);
            utils::XorBlockWithOffset(std::span{p_out, process_size}, std::span{in, process_size},
                                      std::span{key_cache_}, std::size_t{offset_});
            offset_ += process_size;
            in += process_size;
            p_out += process_size;
            len -= process_size;
        }

        const auto other_page_key =
            std::span<const uint8_t, kStaticCipherPageSize>{key_cache_.cbegin(), kStaticCipherPageSize};
        utils::XorBlockWithOffset(std::span{p_out, len}, std::span{in, len}, other_page_key, std::size_t{offset_});
        offset_ += len;

        return true;
    }

    bool End() override
    {
        return !InErrorState();
    }

  private:
    static constexpr std::size_t GetIndexOffset()
    {
        if constexpr (QMC1_TYPE == QMCv1Type::kStaticCipher)
        {
            return 80923;
        }
        else if constexpr (QMC1_TYPE == QMCv1Type::kMapCipher)
        {
            return 71214;
        }
        else
        {
            assert(("unsupported QMC1_TYPE", 0));
            return 0;
        }
    }

    inline void SetKey(QMCv1KeyInput key)
    {
        assert(("key should not be empty", !key.empty()));

        constexpr std::size_t kIndexOffset = GetIndexOffset();
        for (std::size_t i = 0; i < key_cache_.size(); i++)
        {
            std::size_t index = (i * i + kIndexOffset) % key.size();
            key_cache_[i] = key[index];
        }
    }
};

} // namespace tencent::detail

std::unique_ptr<StreamDecryptor> CreateQMCv1StaticDecryptor(tencent::QMCv1KeyInput key)
{
    using namespace tencent::detail;
    return std::make_unique<QMCv1Decryptor<QMCv1Type::kStaticCipher>>(key);
}

std::unique_ptr<StreamDecryptor> CreateQMCv1MapDecryptor(tencent::QMCv1KeyInput key)
{
    using namespace tencent::detail;
    return std::make_unique<QMCv1Decryptor<QMCv1Type::kMapCipher>>(key);
}

} // namespace parakeet_crypto::decryptor
