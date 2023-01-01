#include "XimalayaScrambleTableGeneration.h"

#include "parakeet-crypto/decryptor/ximalaya/XimalayaFileLoader.h"
#include "utils/StringHelper.h"
#include "utils/XorHelper.h"

#include <algorithm>
#include <array>

#include <cassert>

namespace parakeet_crypto::decryptor {

namespace ximalaya::detail {

enum class State {
    kDecryptHeader = 0,
    kPassThrough,
};

class XimalayaFileLoaderImpl : public StreamDecryptor {
   private:
    std::string name_;
    std::array<uint8_t, kX3MContentKeySize> content_key_;
    ximalaya::ScrambleTable scramble_table_;
    State state_ = State::kDecryptHeader;

   public:
    XimalayaFileLoaderImpl(std::span<const uint8_t, kX3MContentKeySize> content_key,
                           std::span<const uint16_t, kXmlyScrambleTableSize> scramble_table,
                           const char* subtype) {
        name_ = utils::Format("Ximalaya(%s)", subtype);
        std::ranges::copy(content_key.begin(), content_key.end(), content_key_.begin());
        std::ranges::copy(scramble_table.begin(), scramble_table.end(), scramble_table_.begin());
    }

    std::string GetName() const override { return name_; };

    inline void HandleHeaderDecryption(const uint8_t*& in, std::size_t& len) {
        if (ReadUntilOffset(in, len, kXmlyScrambleTableSize)) {
            auto p_out = ExpandOutputBuffer(kXmlyScrambleTableSize);
            auto p_in = std::span{buf_in_.cbegin(), kXmlyScrambleTableSize};

            for (std::size_t i = 0; i < kXmlyScrambleTableSize; i++) {
                p_out[i] = p_in[scramble_table_[i]];
            }

            utils::XorBlockWithOffset(std::span{p_out, kXmlyScrambleTableSize}, std::span{content_key_}, 0u);

            EraseInput(kXmlyScrambleTableSize);
            state_ = State::kPassThrough;
        }
    }

    bool Write(const uint8_t* in, std::size_t len) override {
        while (len && !InErrorState()) {
            switch (state_) {
                case State::kDecryptHeader:
                    HandleHeaderDecryption(in, len);
                    break;

                case State::kPassThrough:
                    buf_out_.insert(buf_out_.end(), in, in + len);
                    return true;
            }
        }

        return !InErrorState();
    };

    bool End() override { return !InErrorState(); }
};

}  // namespace ximalaya::detail

using ximalaya::kX2MContentKeySize;
using ximalaya::kX3MContentKeySize;
using ximalaya::kXmlyScrambleTableSize;
using ximalaya::ScrambleTable;

void UpgradeX2MKey(std::span<uint8_t, kX3MContentKeySize> x3m_key,
                   std::span<const uint8_t, kX2MContentKeySize> x2m_key) {
    static_assert(kX3MContentKeySize % kX2MContentKeySize == 0, "Should be a complete block");
    for (std::size_t i = 0; i < kX3MContentKeySize; i += kX2MContentKeySize) {
        std::copy_n(x2m_key.begin(), kX2MContentKeySize, x3m_key.begin() + i);
    }
}

std::unique_ptr<StreamDecryptor> CreateXimalayaDecryptor(
    std::span<const uint8_t> content_key,
    std::span<const uint16_t, kXmlyScrambleTableSize> scramble_table) {
    switch (content_key.size()) {
        case kX2MContentKeySize: {
            std::array<uint8_t, kX3MContentKeySize> upgraded_key;
            UpgradeX2MKey(upgraded_key, std::span<const uint8_t, kX2MContentKeySize>{content_key});
            return std::make_unique<ximalaya::detail::XimalayaFileLoaderImpl>(upgraded_key, scramble_table, "X2M");
        }

        case kX3MContentKeySize:
            return std::make_unique<ximalaya::detail::XimalayaFileLoaderImpl>(content_key.first<kX3MContentKeySize>(),
                                                                              scramble_table, "X3M");

        default:
            return nullptr;
    }
}

std::unique_ptr<StreamDecryptor> CreateXimalayaDecryptor(std::span<const uint8_t> content_key,
                                                         double init_value,
                                                         double step_value) {
    ScrambleTable scramble_table;
    ximalaya::GenerateScrambleTable(scramble_table, init_value, step_value);
    return CreateXimalayaDecryptor(content_key, scramble_table);
}
}  // namespace parakeet_crypto::decryptor
