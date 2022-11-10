#pragma once

#include "parakeet-crypto/decryption/DecryptionStream.h"

namespace parakeet_crypto::decryption::ximalaya {

constexpr std::size_t kX2MContentKeySize = 0x04;
constexpr std::size_t kX3MContentKeySize = 0x20;
constexpr std::size_t kScrambleTableSize = 0x400;

typedef std::array<uint8_t, kX2MContentKeySize> X2MContentKey;
typedef std::array<uint8_t, kX3MContentKeySize> X3MContentKey;
typedef std::array<uint16_t, kScrambleTableSize> ScrambleTable;

class XimalayaFileLoader : public DecryptionStream {
 public:
  virtual const std::string GetName() const override { return "Ximalaya"; };

  static std::unique_ptr<XimalayaFileLoader> Create(const X2MContentKey& key, const ScrambleTable& scramble_table);

  static std::unique_ptr<XimalayaFileLoader> Create(const X3MContentKey& key, const ScrambleTable& scramble_table);
};

}  // namespace parakeet_crypto::decryption::ximalaya
