#include "parakeet-crypto/decryptor/xiami/XiamiFileLoader.h"

#include "utils/EndianHelper.h"
#include "utils/StringHelper.h"
#include "utils/XorHelper.h"

namespace parakeet_crypto::decryptor::xiami {

namespace detail {

constexpr std::size_t kHeaderSize = 0x10;

// 'ifmt +' \xfe *4
constexpr uint32_t kMagicHeader1 = 0x69'66'6D'74;
constexpr uint32_t kMagicHeader2 = 0xfe'fe'fe'fe;

constexpr std::size_t kMagicHeaderOffset1 = 0x00;
constexpr std::size_t kMagicHeaderOffset2 = 0x08;
constexpr std::size_t kKeyDataOffset = 0x0C;

enum class State {
    kReadHeader = 0,
    kTransparentCopy,
    kDecryptWithKey,
};

// Xiami file header
// offset  description
//   0x00  "ifmt"
//   0x04  Format name, e.g. "FLAC".
//   0x08  0xfe, 0xfe, 0xfe, 0xfe
//   0x0C  (3 bytes) Little-endian, size of data to copy without modification.
//         e.g. [ 8a 19 00 ] = 6538 bytes of plaintext data.
//   0x0F  (1 byte) File key, applied to
//   0x10  Plaintext data
//   ????  Encrypted data

class XiamiFileLoaderImpl : public XiamiFileLoader {
   private:
    State state_ = State::kReadHeader;
    std::size_t bytes_to_copy_ = 0;
    uint8_t file_key_ = 0;

   public:
    XiamiFileLoaderImpl() = default;

    virtual const std::string GetName() const override { return "Xiami"; };

    bool ParseFileHeader() {
        if (ReadBigEndian<uint32_t>(&buf_in_[kMagicHeaderOffset1]) != kMagicHeader1 ||
            ReadBigEndian<uint32_t>(&buf_in_[kMagicHeaderOffset2]) != kMagicHeader2) {
            return false;
        }

        // u24_LE transparent size + uint8_t file key
        uint32_t temp = ReadLittleEndian<uint32_t>(&buf_in_[kKeyDataOffset]);
        file_key_ = (temp >> 24) - 1;
        bytes_to_copy_ = temp & 0x00'FF'FF'FF;
        return true;
    }

    void HandleFileHeader(const uint8_t*& in, std::size_t& len) {
        if (ReadUntilOffset(in, len, kHeaderSize)) {
            if (!ParseFileHeader()) {
                error_ = "file header magic not found";
            } else {
                buf_in_.erase(buf_in_.begin(), buf_in_.begin() + kHeaderSize);
                state_ = State::kTransparentCopy;
            }
        }
    }

    void HandleTransparentCopy(const uint8_t*& in, std::size_t& len) {
        std::size_t copy_len = std::min(bytes_to_copy_, len);
        buf_out_.insert(buf_out_.end(), in, in + copy_len);

        in += copy_len;
        len -= copy_len;
        bytes_to_copy_ -= copy_len;
        offset_ += copy_len;

        if (bytes_to_copy_ == 0) {
            state_ = State::kDecryptWithKey;
        }
    }

    void HandleDecryptWithKey(const uint8_t*& in, std::size_t& len) {
        uint8_t* p_out = ExpandOutputBuffer(len);

        for (std::size_t i = 0; i < len; i++) {
            p_out[i] = file_key_ - in[i];
        }

        len = 0;
    }

    bool Write(const uint8_t* in, std::size_t len) override {
        while (len && !InErrorState()) {
            switch (state_) {
                case State::kReadHeader:
                    HandleFileHeader(in, len);
                    break;

                case State::kTransparentCopy:
                    HandleTransparentCopy(in, len);
                    break;

                case State::kDecryptWithKey:
                    HandleDecryptWithKey(in, len);
                    break;

                default:
                    error_ = "decryptor: bad state";
                    return false;
            }
        }

        return !InErrorState();
    };

    bool End() override { return !InErrorState(); }
};

}  // namespace detail

std::unique_ptr<XiamiFileLoader> XiamiFileLoader::Create() {
    return std::make_unique<detail::XiamiFileLoaderImpl>();
}

}  // namespace parakeet_crypto::decryptor::xiami
