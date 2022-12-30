#include "parakeet-crypto/decryptor/kugou/KugouFileLoader.h"

#include "KGMCrypto.h"
#include "KGMHeaderStruct.h"

#include "utils/EndianHelper.h"
#include "utils/StringHelper.h"
#include "utils/XorHelper.h"

#include <cassert>
#include <cstring>

namespace parakeet_crypto::decryptor {
// Private implementation

namespace kugou::detail {

constexpr std::size_t kMinimalHeaderSize = 0x2c;
using KugouSlotKey1 = std::array<uint8_t, 4>;

enum class State {
    kReadHeader = 0,
    kSeekToEncryptedContent,
    kDecryptContent,
};

class KugouFileLoaderImpl : public StreamDecryptor {
   public:
    explicit KugouFileLoaderImpl(const KGMCryptoConfig& config) : config_(config) {}
    std::string GetName() const override { return "Kugou"; };

   private:
    size_t header_size_ = 0;
    std::unique_ptr<KGMCrypto> decryptor_ = nullptr;
    KGMCryptoConfig config_;
    State state_ = State::kReadHeader;

    inline void HandleDecryptContent(const uint8_t*& in, std::size_t& len) {
        auto p_out = ExpandOutputBuffer(len);
        std::copy_n(in, len, p_out);

        decryptor_->Decrypt(offset_, std::span{p_out, len});

        offset_ += len;
        len = 0;
    }

    inline void HandleSeekToContent(const uint8_t*& in, std::size_t& len) {
        if (ReadUntilOffset(in, len, header_size_)) {
            buf_in_.erase(buf_in_.begin(), buf_in_.begin() + header_size_);
            offset_ = 0;
            state_ = State::kDecryptContent;
        }
    }

    inline void HandleReadFileHeader(const uint8_t*& in, std::size_t& len) {
        if (ReadUntilOffset(in, len, sizeof(kgm_file_header))) {
            kgm_file_header header;
            memcpy(&header, buf_in_.data(), sizeof(header));
            header_size_ = header.offset_to_data;

            decryptor_ = CreateKGMDecryptor(header, config_);
            if (decryptor_ == nullptr) {
                error_ = "could not find a valid decryptor";
            } else {
                state_ = State::kSeekToEncryptedContent;
            }
        }
    }

    bool Write(const uint8_t* in, std::size_t len) override {
        while (len && InErrorState()) {
            using enum State;

            switch (state_) {
                case kReadHeader:
                    HandleReadFileHeader(in, len);
                    break;

                case kSeekToEncryptedContent:
                    HandleSeekToContent(in, len);
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
    }

    bool End() override { return true; }
};

}  // namespace kugou::detail

// Public interface

std::unique_ptr<StreamDecryptor> CreateKugouDecryptor(const KugouSlotKeys& slot_keys,
                                                      std::span<const uint8_t> v4_slot_key_expansion_table,
                                                      std::span<const uint8_t> v4_file_key_expansion_table) {
    std::vector<uint8_t> v4_slot_key_table_vec(v4_slot_key_expansion_table.begin(), v4_slot_key_expansion_table.end());
    std::vector<uint8_t> v4_file_key_table_vec(v4_file_key_expansion_table.begin(), v4_file_key_expansion_table.end());

    auto config = kugou::KGMCryptoConfig{
        .slot_keys = slot_keys,
        .v4_slot_key_expansion_table = v4_slot_key_table_vec,
        .v4_file_key_expansion_table = v4_file_key_table_vec,
    };
    return std::make_unique<kugou::detail::KugouFileLoaderImpl>(config);
}

}  // namespace parakeet_crypto::decryptor
