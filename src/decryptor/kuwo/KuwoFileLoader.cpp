#include "parakeet-crypto/decryptor/kuwo/KuwoFileLoader.h"
#include "utils/EndianHelper.h"
#include "utils/StringHelper.h"

#include "utils/XorHelper.h"

#include <cinttypes>

namespace parakeet_crypto::decryption::kuwo {

namespace detail {

constexpr std::size_t kFileHeaderSize = 0x20;
constexpr std::size_t kFileKeyOffset = 0x18;
constexpr std::size_t kFullHeaderSize = 0x400;

const std::array<uint8_t, 0x10> kKuwoMagicHeader1 = {
    0x79, 0x65, 0x65, 0x6c, 0x69, 0x6f, 0x6e, 0x2d, 0x6b, 0x75, 0x77, 0x6f, 0x2d, 0x74, 0x6d, 0x65,
};

const std::array<uint8_t, 0x10> kKuwoMagicHeader2 = {
    0x79, 0x65, 0x65, 0x6c, 0x69, 0x6f, 0x6e, 0x2d, 0x6b, 0x75, 0x77, 0x6f, 0x00, 0x00, 0x00, 0x00,
};

enum class State {
  kWaitForHeader = 0,
  kSeekToBody,
  kDecrypt,
};

class KuwoFileLoaderImpl : public KuwoFileLoader {
 private:
  KuwoKey key_;
  State state_ = State::kWaitForHeader;

 public:
  KuwoFileLoaderImpl(const KuwoKey& key) : key_(key) {}

  inline void InitCache() {
    uint64_t resource_id = ReadLittleEndian<uint64_t>(&buf_in_[kFileKeyOffset]);
    auto rid_str = utils::Format("%" PRIu64, resource_id);
    XorBlock(key_.data(), key_.size(), rid_str.data(), rid_str.length(), 0);
  }

  inline void Decrypt(const uint8_t* in, std::size_t len) {
    uint8_t* p_out = ExpandOutputBuffer(len);

    XorBlock(p_out, in, len, key_.data(), key_.size(), offset_);
    offset_ += len;
  }

  bool Write(const uint8_t* in, std::size_t len) override {
    while (len) {
      switch (state_) {
        case State::kWaitForHeader:
          if (ReadUntilOffset(in, len, kFileHeaderSize)) {
            // Validate header.
            if (!std::equal(kKuwoMagicHeader1.begin(), kKuwoMagicHeader1.end(), buf_in_.begin()) &&
                !std::equal(kKuwoMagicHeader2.begin(), kKuwoMagicHeader2.end(), buf_in_.begin())) {
              error_ = "file header magic not found";
              return false;
            }

            InitCache();
            state_ = State::kSeekToBody;
          }
          break;

        case State::kSeekToBody:
          if (ReadUntilOffset(in, len, kFullHeaderSize)) {
            buf_in_.erase(buf_in_.begin(), buf_in_.begin() + kFullHeaderSize);
            state_ = State::kDecrypt;
          }
          break;

        case State::kDecrypt:
          Decrypt(in, len);
          return true;
      }
    }

    return len == 0;
  };

  bool End() override { return !InErrorState(); }
};

}  // namespace detail

std::unique_ptr<KuwoFileLoader> KuwoFileLoader::Create(const KuwoKey& key) {
  return std::make_unique<detail::KuwoFileLoaderImpl>(key);
}

}  // namespace parakeet_crypto::decryption::kuwo
