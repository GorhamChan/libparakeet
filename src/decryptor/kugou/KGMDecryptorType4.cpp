#include "KGMDecryptor.h"

#include "utils/base64.h"
#include "utils/hex.h"
#include "utils/md5.h"

#include <algorithm>
#include <span>
#include <vector>

namespace parakeet_crypto::decryptor::kugou {

constexpr size_t V4_DIGEST_SIZE = 31;
class KGMCryptoType4 : public KGMCrypto {
 private:
  std::vector<uint8_t> slot_key_;
  std::vector<uint8_t> file_key_;

  static std::array<uint8_t, V4_DIGEST_SIZE> hash_type4(const std::span<const uint8_t> data) {
    static const std::array DIGEST_INDEXES = {
        0x05, 0x0e, 0x0d, 0x02, 0x0c, 0x0a, 0x0f, 0x0b, 0x03, 0x08, 0x05, 0x06, 0x09, 0x04, 0x03, 0x07,
        0x00, 0x0e, 0x0d, 0x06, 0x02, 0x0c, 0x0a, 0x0f, 0x01, 0x0b, 0x08, 0x07, 0x09, 0x04, 0x01,
    };

    std::array<uint8_t, V4_DIGEST_SIZE> result;
    auto digest = utils::md5(data);
    for (int i = 0; i < V4_DIGEST_SIZE; i++) {
      result[i] = digest[DIGEST_INDEXES[i]];
    }
    return result;
  }

  static std::vector<uint8_t> key_expansion(const std::span<const uint8_t> table, const std::span<const uint8_t> key) {
    auto md5_final = hash_type4(key);

    auto table_len = table.size();
    auto md5_final_len = md5_final.size();
    auto final_key_size = 4 * (md5_final_len - 1) * (table_len - 1);

    std::vector<uint8_t> expanded_key;
    expanded_key.reserve(final_key_size);
    for (uint32_t i = 1; i < static_cast<uint32_t>(md5_final_len); i++) {
      uint32_t temp1 = i * static_cast<uint32_t>(md5_final[i]);

      for (uint32_t j = 1; j < static_cast<uint32_t>(table_len); j++) {
        uint32_t temp = temp1 * j * static_cast<uint32_t>(table[j]);

        expanded_key.push_back(static_cast<uint8_t>(temp >> 0x00));
        expanded_key.push_back(static_cast<uint8_t>(temp >> 0x18));
        expanded_key.push_back(static_cast<uint8_t>(temp >> 0x10));
        expanded_key.push_back(static_cast<uint8_t>(temp >> 0x08));
      }
    }

    return expanded_key;
  }

  inline void configureSlotKey(const KGMCryptoConfig& config, const std::vector<uint8_t>& slot_key) {
    using namespace parakeet_crypto::utils;
    auto slot_key_md5 = utils::md5(slot_key);
    auto md5_hex = HexCompactLowercase(slot_key_md5);
    auto md5_b64 = Base64EncodeBytes(std::span{reinterpret_cast<uint8_t*>(md5_hex.data()), md5_hex.size()});
    slot_key_ = key_expansion(config.v4_slot_key_expansion_table, md5_b64);
  }

  inline void configureFileKey(const KGMCryptoConfig& config, const kgm_file_header& header) {
    file_key_ = key_expansion(config.v4_file_key_expansion_table, std::span{header.key});
  }

 public:
  bool Configure(const KGMCryptoConfig& config,
                 const std::vector<uint8_t>& slot_key,
                 const kgm_file_header& header) override {
    configureSlotKey(config, slot_key);
    configureFileKey(config, header);

    return true;
  }

  void Encrypt(uint64_t offset, std::span<uint8_t> buffer) override {
    std::ranges::transform(buffer.begin(), buffer.end(), buffer.begin(), [&offset, this](auto v) {
      uint8_t offset_key = xor_u32_bytes(static_cast<uint32_t>(offset));
      uint8_t slot_key = slot_key_[offset % slot_key_.size()];
      uint8_t file_key = file_key_[offset % file_key_.size()];

      v ^= offset_key;
      v ^= slot_key;
      v ^= v << 4;
      v ^= file_key;

      offset++;
      return v;
    });
  }

  void Decrypt(uint64_t offset, std::span<uint8_t> buffer) override {
    std::ranges::transform(buffer.begin(), buffer.end(), buffer.begin(), [&offset, this](auto v) {
      uint8_t offset_key = xor_u32_bytes(static_cast<uint32_t>(offset));
      uint8_t slot_key = slot_key_[offset % slot_key_.size()];
      uint8_t file_key = file_key_[offset % file_key_.size()];

      v ^= file_key;
      v ^= v << 4;
      v ^= slot_key;
      v ^= offset_key;

      offset++;
      return v;
    });
  }
};

std::unique_ptr<KGMCrypto> CreateKGMDecryptorType4() {
  return std::make_unique<KGMCryptoType4>();
}

}  // namespace parakeet_crypto::decryptor::kugou
