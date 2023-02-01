#include "parakeet-crypto/decryptor/joox/JooxFileLoader.h"
#include "utils/EndianHelper.h"

#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>

#include <cassert>

#include "utils/hex.h"
#include <iostream>

namespace parakeet_crypto::decryptor
{

// Private implementation

namespace joox::detail_joox_v4
{
using CryptoAES = CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption;

constexpr std::size_t kMagicSize = 4;
constexpr std::size_t kVer4HeaderSize = 12; /* 'E!04' + uint64_t_be(file size) */

constexpr uint32_t kMagicJooxV4 = 0x45'21'30'34; // 'E!04'

// Input block + padding 16 bytes (of 0x10)
constexpr std::size_t kAESBlockSize = 0x10;
constexpr std::size_t kEncryptionBlockSize = 0x100000; // 1MiB
constexpr std::size_t kDecryptionBlockSize = kEncryptionBlockSize + 0x10;
constexpr std::size_t kBlockCountPerIteration = kEncryptionBlockSize / kAESBlockSize;

enum class State
{
    kWaitForHeader = 1,
    kDecryptSingleBlock,
    kDecryptAndVerifyPaddingBlock,
};

class JooxFileLoaderImpl : public StreamDecryptor
{
  public:
    JooxFileLoaderImpl(const std::string &install_uuid, std::span<const uint8_t> salt) : uuid_(install_uuid)
    {
        assert(salt.size() == salt_.size());
        std::copy_n(salt.begin(), std::min(salt_.size(), salt.size()), salt_.begin());
    }
    ~JooxFileLoaderImpl() final = default;
    std::string GetName() const override
    {
        return "joox";
    };

  private:
    CryptoAES aes_;

    std::string uuid_;
    JooxSalt salt_;
    State state_ = State::kWaitForHeader;
    std::size_t block_count_ = 0;

    inline void SetupKey()
    {
        std::array<uint8_t, CryptoPP::SHA1::DIGESTSIZE> derived_key;
        CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA1> pbkdf;
        pbkdf.DeriveKey(&derived_key[0], derived_key.size(), 0 /* unused */,
                        reinterpret_cast<const uint8_t *>(uuid_.c_str()), uuid_.size(), salt_.data(), salt_.size(),
                        1000, 0);

        aes_.SetKey(derived_key.data(), kAESBlockSize);
    }

    inline void HandleWaitForHeader(const uint8_t *&in, std::size_t &len)
    {
        if (ReadBlock(in, len, kVer4HeaderSize))
        {
            const std::array<const uint8_t, 4> kJooxMagicHeader = {'E', '!', '0', '4'};
            if (std::equal(kJooxMagicHeader.begin(), kJooxMagicHeader.end(), buf_in_.begin()))
            {
                ConsumeInput(kVer4HeaderSize);
                SetupKey();
                block_count_ = 0;
                state_ = State::kDecryptSingleBlock;
            }
            else
            {
                error_ = "joox v4 header magic not found";
            }
        }
    }

    inline void HandleFirstPageDecryption(const uint8_t *&in, std::size_t &len)
    {
        // Always reserve last 16 bytes, reserve the padding block.
        while (ReadBlock(in, len, kAESBlockSize * 2))
        {
            ConsumeAndDecryptSingleAesBlock();
            block_count_++;
            if (block_count_ == kBlockCountPerIteration)
            {
                state_ = State::kDecryptAndVerifyPaddingBlock;
                return;
            }
        }
    }

    inline void HandleDecryptPaddingBlock(const uint8_t *&in, std::size_t &len)
    {
        if (ReadBlock(in, len, kAESBlockSize))
        {
            if (!DecryptPaddingBlock())
            {
                error_ = "Could not verify aes-padding.";
                return;
            }
            state_ = State::kDecryptSingleBlock;
            block_count_ = 0;
        }
    }

    bool Write(const uint8_t *in, std::size_t len) override
    {
        buf_out_.reserve(buf_out_.size() + len);

        while (len && !InErrorState())
        {
            using enum parakeet_crypto::decryptor::joox::detail_joox_v4::State;

            switch (state_)
            {
            case kWaitForHeader:
                HandleWaitForHeader(in, len);
                break;

            case kDecryptSingleBlock:
                HandleFirstPageDecryption(in, len);
                break;

            case kDecryptAndVerifyPaddingBlock:
                HandleDecryptPaddingBlock(in, len);
                break;

            default:
                error_ = "unexpected state";
                return false;
            }
        }

        return true;
    }

    inline void ConsumeAndDecryptSingleAesBlock()
    {
        auto p_out = ExpandOutputBuffer(kAESBlockSize);

        aes_.ProcessData(p_out, buf_in_.data(), kAESBlockSize);

        ConsumeInput(kAESBlockSize);
    }

    inline bool DecryptPaddingBlock()
    {
        std::array<uint8_t, kAESBlockSize> block;
        aes_.ProcessData(block.data(), buf_in_.data(), kAESBlockSize);

        // Trim data. It should be 1 <= trim <= 16.
        uint8_t trim = block[kAESBlockSize - 1];
        if (trim == 0 || trim > 16)
        {
            error_ = "pkcs5 padding validation failed: out of range";
            return false;
        }

        std::size_t len = kAESBlockSize - trim;

        uint8_t zero_sum = 0;
        for (std::size_t i = len; i < kAESBlockSize; i++)
        {
            zero_sum |= block[i] ^ trim;
        }

        if (zero_sum != 0)
        {
            error_ = "pkcs5 padding validation failed: mismatch padding";
            return false;
        }

        buf_out_.insert(buf_out_.end(), block.begin(), block.begin() + len);

        ConsumeInput(kAESBlockSize);
        return true;
    }

    bool End() override
    {
        if (InErrorState())
            return false;
        if (buf_in_.empty())
            return true;

        if (buf_in_.size() != kAESBlockSize)
        {
            error_ = "unexpected file EOF";
            return false;
        }

        // Last block.
        return DecryptPaddingBlock();
    }
};

} // namespace joox::detail_joox_v4

// Public interface

std::unique_ptr<StreamDecryptor> CreateJooxDecryptor(const std::string &install_uuid, joox::JooxSaltInput salt)
{
    return std::make_unique<joox::detail_joox_v4::JooxFileLoaderImpl>(install_uuid, salt);
}

} // namespace parakeet_crypto::decryptor
