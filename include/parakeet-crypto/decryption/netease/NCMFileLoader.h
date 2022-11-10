#pragma once

#include "parakeet-crypto/decryption/DecryptionStream.h"

#include <array>
#include <memory>
#include <string>

#include <cstdint>

namespace parakeet_crypto::decryption::netease {

// AES Key; which can be used to decrypt the embedded "content key"
constexpr std::size_t kNCMContentKeyProtectionKeySize = 128 / 8;
typedef std::array<uint8_t, kNCMContentKeyProtectionKeySize> NCMContentKeyProtectionKey;

class NCMFileLoader : public DecryptionStream {
 public:
  virtual const std::string GetName() const override { return "NCM"; };

  static std::unique_ptr<NCMFileLoader> Create(const NCMContentKeyProtectionKey& key);
};

}  // namespace parakeet_crypto::decryption::netease
