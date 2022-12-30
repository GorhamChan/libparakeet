#include "parakeet-crypto/decryptor/kugou/KugouFileLoader.h"

#include "KGMDecryptor.h"
#include "KugouHeader.h"

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
  kReadFileMagic = 0,
  kWaitForHeader,
  kSeekToBody,
  kDecrypt,
};

class KugouFileLoaderImpl : public StreamDecryptor {
 public:
  KugouFileLoaderImpl(const KGMCryptoConfig& config) : config_(config) {}
  virtual const std::string GetName() const override { return "Kugou"; };

 private:
  size_t header_size_ = 0;
  std::unique_ptr<KGMCrypto> decryptor_ = nullptr;
  KGMCryptoConfig config_;
  State state_ = State::kReadFileMagic;

  inline void DecryptInput(const uint8_t*& in, std::size_t& len) {
    auto p_out = ExpandOutputBuffer(len);
    std::copy_n(in, len, p_out);

    decryptor_->Decrypt(offset_, p_out, len);

    offset_ += len;
    len = 0;
  }

  bool Write(const uint8_t* in, std::size_t len) override {
    while (len) {
      switch (state_) {
        case State::kReadFileMagic:
          if (ReadUntilOffset(in, len, sizeof(kgm_file_header))) {
            kgm_file_header header;
            memcpy(&header, buf_in_.data(), sizeof(header));
            header_size_ = header.offset_to_data;

            decryptor_ = create_kugou_decryptor(header, config_);
            if (decryptor_ == nullptr) {
              error_ = true;
              return false;
            }

            state_ = State::kSeekToBody;
          }
          break;

        case State::kSeekToBody:
          if (ReadUntilOffset(in, len, header_size_)) {
            buf_in_.erase(buf_in_.begin(), buf_in_.begin() + header_size_);
            offset_ = 0;
            state_ = State::kDecrypt;
          }
          break;

        case State::kDecrypt:
          DecryptInput(in, len);
          break;
      }
    }

    assert(len == 0);

    return true;
  }

  virtual bool End() override { return true; }
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
