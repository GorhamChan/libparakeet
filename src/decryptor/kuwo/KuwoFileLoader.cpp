#include "parakeet-crypto/decryptor/kuwo/KuwoFileLoader.h"

#include "utils/EndianHelper.h"
#include "utils/StringHelper.h"
#include "utils/XorHelper.h"

#include <algorithm>
#include <cinttypes>

namespace parakeet_crypto::decryptor {

namespace kuwo::detail {

constexpr std::size_t kFileHeaderSize = 0x20;
constexpr std::size_t kFileKeyOffset = 0x18;
constexpr std::size_t kFullHeaderSize = 0x400;

enum class State {
    kParseHeader = 0,
    kSeekToDecryptionContent,
    kDecryptContent,
};

class KuwoFileLoaderImpl : public StreamDecryptor {
   private:
    KuwoKey key_;
    State state_ = State::kParseHeader;

   public:
    explicit KuwoFileLoaderImpl(std::span<const uint8_t, kKuwoDecryptionKeySize> key) {
        std::ranges::copy(key.begin(), key.end(), key_.begin());
    }
    std::string GetName() const override { return "Kuwo"; };

    inline void InitCache() {
        uint64_t resource_id = ReadLittleEndian<uint64_t>(&buf_in_[kFileKeyOffset]);
        auto rid_str = utils::Format("%" PRIu64, resource_id);
        auto rid_span = std::span{rid_str};

        for (auto i = 0; i < key_.size(); i++) {
            key_[i] ^= static_cast<uint8_t>(rid_span[i % rid_span.size()]);
        }
    }

    inline void HandleParseHeader(const uint8_t*& in, std::size_t& len) {
        if (ReadUntilOffset(in, len, kFileHeaderSize)) {
            const static auto kKuwoMagicHeader1 = std::to_array<uint8_t>(
                {'y', 'e', 'e', 'l', 'i', 'o', 'n', '-', 'k', 'u', 'w', 'o', '-', 't', 'm', 'e'});

            const static auto kKuwoMagicHeader2 = std::to_array<uint8_t>(
                {'y', 'e', 'e', 'l', 'i', 'o', 'n', '-', 'k', 'u', 'w', 'o', 0x00, 0x00, 0x00, 0x00});

            // Validate header.
            if (!std::equal(kKuwoMagicHeader1.cbegin(), kKuwoMagicHeader1.cend(), buf_in_.cbegin()) &&
                !std::equal(kKuwoMagicHeader2.cbegin(), kKuwoMagicHeader2.cend(), buf_in_.cbegin())) {
                error_ = "file header magic not found";
            } else {
                InitCache();
                state_ = State::kSeekToDecryptionContent;
            }
        }
    }

    inline void HandleSeekToDecryptionContent(const uint8_t*& in, std::size_t& len) {
        if (ReadUntilOffset(in, len, kFullHeaderSize)) {
            EraseInput(kFullHeaderSize);
            state_ = State::kDecryptContent;
        }
    }

    inline void HandleDecryptContent(const uint8_t*& in, std::size_t& len) {
        uint8_t* p_out = ExpandOutputBuffer(len);

        utils::XorBlockWithOffset(std::span{p_out, len}, std::span{in, len},
                                  std::span<uint8_t, kKuwoDecryptionKeySize>{key_}, offset_);

        offset_ += len;
        in += len;
        len = 0;
    }

    bool Write(const uint8_t* in, std::size_t len) override {
        while (len && !InErrorState()) {
            using enum State;

            switch (state_) {
                case kParseHeader:
                    HandleParseHeader(in, len);
                    break;

                case kSeekToDecryptionContent:
                    HandleSeekToDecryptionContent(in, len);
                    break;

                case kDecryptContent:
                    HandleDecryptContent(in, len);
                    break;

                default:
                    error_ = "unexpected state";
                    break;
            }
        }

        return !InErrorState();
    };

    bool End() override { return !InErrorState(); }
};

}  // namespace kuwo::detail

std::unique_ptr<StreamDecryptor> CreateKuwoDecryptor(std::span<const uint8_t, kKuwoDecryptionKeySize> key) {
    return std::make_unique<kuwo::detail::KuwoFileLoaderImpl>(key);
}

}  // namespace parakeet_crypto::decryptor
