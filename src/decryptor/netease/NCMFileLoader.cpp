#include "parakeet-crypto/decryptor/netease/NCMFileLoader.h"

#include "NeteaseRC4.h"

#include "utils/EndianHelper.h"
#include "utils/StringHelper.h"
#include "utils/XorHelper.h"

#include "cryptopp/aes.h"
#include "cryptopp/filters.h"
#include "cryptopp/modes.h"

#include <ranges>
#include <span>

namespace parakeet_crypto::decryptor {

namespace netease::detail {

/**
 * @brief NCM file format
 *
 * File header: Hardcoded 8 char + 2 padding (hardcoded?)
 * 0000h: 43 54 45 4E 46 44 41 4D 01 69  CTENFDAM.i
 *
 * Followed by 3 blocks:
 *   - Content Key (Encrypted using `NCMContentKeyProtectionKey`)
 *   - Metadata; (Encrypted, ignored by this library)
 *   - Album Cover (prefixed with 5 bytes padding? ignored by this library);
 *   - Audio Data (Encrypted with Content Key);
 */

constexpr std::size_t kFileHeaderSize = 10;  // 'CTENFDAM'

enum class State {
    kReadFileMagic = 0,

    kParseFileKey,
    kReadMetaBlock,
    kReadCoverBlock,
    kSkipCoverPadding,
    kDecryptAudio
};

class NCMFileLoaderImpl : public StreamDecryptor {
   private:
    State state_ = State::kReadFileMagic;
    NCMContentKeyProtectionKey key_;

    uint32_t content_key_size_ = 0;
    uint32_t metadata_size_ = 0;
    uint32_t cover_container_size_ = 0;
    uint32_t cover_size_ = 0;

    std::size_t audio_data_offset_ = 0;
    std::array<uint8_t, 0x100> final_audio_xor_key_;

   public:
    explicit NCMFileLoaderImpl(NCMContentKeyProtectionKeyInput key) { std::ranges::copy(key, key_.begin()); }
    std::string GetName() const override { return "NCM"; };

    bool ParseFileKey() {
        using AES = CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption;
        using Filter = CryptoPP::StreamTransformationFilter;

        std::vector<uint8_t> content_key;

        std::vector<uint8_t> file_key(content_key_size_);
        ConsumeInput(file_key);
        std::ranges::transform(file_key, file_key.begin(), [](auto key) { return key ^ 0x64; });

        try {
            AES aes(key_.data(), key_.size());
            Filter decryptor(aes, nullptr, Filter::PKCS_PADDING);
            decryptor.PutMessageEnd(file_key.data(), file_key.size());
            content_key.resize(decryptor.MaxRetrievable());
            decryptor.Get(content_key.data(), content_key.size());
        } catch (const CryptoPP::Exception& ex) {
            error_ = utils::Format("could not decrypt content key: ", ex.what());
            return false;
        }

        const static auto kContentKeyPrefix = std::to_array<uint8_t>(
            {'n', 'e', 't', 'e', 'a', 's', 'e', 'c', 'l', 'o', 'u', 'd', 'm', 'u', 's', 'i', 'c'});

        if (!std::equal(kContentKeyPrefix.cbegin(), kContentKeyPrefix.cend(), content_key.cbegin())) {
            error_ = "invalid key prefix";
            return false;
        }

        RC4 rc4(std::span{content_key}.subspan(kContentKeyPrefix.size()));
        rc4.Derive(final_audio_xor_key_);

        return true;
    }

    bool ReadNextSizedBlock(const uint8_t*& in, std::size_t& len, uint32_t& next_block_size, std::size_t padding = 0) {
        if (InErrorState()) return false;

        if (next_block_size == 0 && ReadBlock(in, len, sizeof(uint32_t))) {
            ConsumeInput(&next_block_size);
            next_block_size = SwapLittleEndianToHost(next_block_size) + static_cast<uint32_t>(padding);

            if (next_block_size == 0) {
                error_ = "file key size = 0";
                return false;
            }
        }

        if (next_block_size > 0 && ReadBlock(in, len, next_block_size)) {
            return true;
        }

        return false;
    }

    inline void HandleReadFileMagic(const uint8_t*& in, std::size_t& len) {
        if (ReadUntilOffset(in, len, kFileHeaderSize)) {
            std::array<uint8_t, kFileHeaderSize> file_header;
            ConsumeInput(file_header);

            const static auto kNCMFileMagic = std::to_array<uint8_t>({'C', 'T', 'E', 'N', 'F', 'D', 'A', 'M'});
            if (!std::equal(kNCMFileMagic.cbegin(), kNCMFileMagic.cend(), file_header.cbegin())) {
                error_ = "not a valid ncm file";
            } else {
                state_ = State::kParseFileKey;
            }
        }
    }

    inline void HandleParseFileKey(const uint8_t*& in, std::size_t& len) {
        if (ReadNextSizedBlock(in, len, content_key_size_)) {
            if (!ParseFileKey()) {
                error_ = "Could not parse file key";
            } else {
                state_ = State::kReadMetaBlock;
            }
        }
    }

    inline void HandleMetaBlock(const uint8_t*& in, std::size_t& len) {
        // unknown 5 bytes padding;
        if (ReadNextSizedBlock(in, len, metadata_size_, 5)) {
            ConsumeInput(std::size_t{metadata_size_});  // discard
            state_ = State::kReadCoverBlock;
        }
    }

    inline void HandleCoverBlock(const uint8_t*& in, std::size_t& len) {
        if (cover_container_size_ == 0 && ReadBlock(in, len, sizeof(cover_container_size_))) {
            // Get the container size.
            ConsumeInput(&cover_container_size_);
            cover_container_size_ = SwapLittleEndianToHost(cover_container_size_);
        }

        if (cover_container_size_ != 0 && ReadNextSizedBlock(in, len, cover_size_)) {
            if (cover_container_size_ < cover_size_) {
                error_ = "cover container size is smaller than cover size.";
            } else {
                ConsumeInput(std::size_t{cover_size_});
                state_ = State::kSkipCoverPadding;
            }
        }
    }

    inline void HandleSkipCoverPadding(const uint8_t*& in, std::size_t& len) {
        if (ReadBlock(in, len, cover_container_size_ - cover_size_)) {
            ConsumeInput(std::size_t{cover_container_size_ - cover_size_});
            state_ = State::kDecryptAudio;
        }
    }

    inline void HandleAudioContentDecryption(const uint8_t*& in, std::size_t& len) {
        auto p_out = ExpandOutputBuffer(len);

        utils::XorBlockWithOffset(std::span{p_out, len}, std::span{in, len}, std::span{final_audio_xor_key_},
                                  audio_data_offset_);

        offset_ += len;
        audio_data_offset_ += len;
        len = 0;
    }

    bool Write(const uint8_t* in, std::size_t len) override {
        while (len && !InErrorState()) {
            using enum State;

            switch (state_) {
                case kReadFileMagic:
                    HandleReadFileMagic(in, len);
                    break;

                case kParseFileKey:
                    HandleParseFileKey(in, len);
                    break;

                case kReadMetaBlock:
                    HandleMetaBlock(in, len);
                    break;

                case kReadCoverBlock:
                    HandleCoverBlock(in, len);
                    break;

                case kSkipCoverPadding:
                    HandleSkipCoverPadding(in, len);
                    break;

                case kDecryptAudio:
                    HandleAudioContentDecryption(in, len);
                    break;

                default:
                    error_ = "decryptor: bad state";
                    return false;
            }
        }

        return !InErrorState();
    };

    bool End() override { return !InErrorState(); };
};

}  // namespace netease::detail

using netease::detail::NCMFileLoaderImpl;

std::unique_ptr<StreamDecryptor> CreateNeteaseDecryptor(netease::NCMContentKeyProtectionKeyInput key) {
    return std::make_unique<NCMFileLoaderImpl>(key);
}

}  // namespace parakeet_crypto::decryptor
