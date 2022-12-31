#include "parakeet-crypto/decryptor/kuwo/KuwoFileLoader.h"
#include "utils/EndianHelper.h"
#include "utils/StringHelper.h"

#include "utils/XorHelper.h"

#include <cinttypes>

#include <algorithm>

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
        XorBlock(key_.data(), key_.size(), rid_str.data(), rid_str.length(), 0);
    }

    inline void HandleParseHeader(const uint8_t*& in, std::size_t& len) {
        if (ReadUntilOffset(in, len, kFileHeaderSize)) {
            const static auto kKuwoMagicHeader1 = std::to_array<uint8_t>(
                {'y', 'e', 'e', 'l', 'i', 'o', 'n', '-', 'k', 'u', 'w', 'o', '-', 't', 'm', 'e'});

            const static auto kKuwoMagicHeader2 = std::to_array<uint8_t>(
                {'y', 'e', 'e', 'l', 'i', 'o', 'n', '-', 'k', 'u', 'w', 'o', 0x00, 0x00, 0x00, 0x00});

            // Validate header.
            if (!std::equal(buf_in_.begin(), buf_in_.begin() + kKuwoMagicHeader1.size(), kKuwoMagicHeader1.begin()) &&
                !std::equal(buf_in_.begin(), buf_in_.begin() + kKuwoMagicHeader2.size(), kKuwoMagicHeader2.begin())) {
                error_ = "file header magic not found";
            } else {
                InitCache();
                state_ = State::kSeekToDecryptionContent;
            }
        }
    }

    inline void HandleSeekToDecryptionContent(const uint8_t* in, std::size_t len) {
        if (ReadUntilOffset(in, len, kFullHeaderSize)) {
            EraseInput(kFullHeaderSize);
            state_ = State::kDecryptContent;
        }
    }

    inline void HandleDecryptContent(const uint8_t* in, std::size_t len) {
        uint8_t* p_out = ExpandOutputBuffer(len);

        XorBlock(p_out, in, len, key_.data(), key_.size(), offset_);
        offset_ += len;
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
                    return true;
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
