#pragma once

#include "parakeet-crypto/decryption/DecryptionStream.h"

namespace parakeet_crypto::decryption::kuwo {

constexpr std::size_t kKuwoDecryptionKeySize = 0x20;
typedef std::array<uint8_t, kKuwoDecryptionKeySize> KuwoKey;

class KuwoFileLoader : public DecryptionStream {
 public:
  virtual const std::string GetName() const override { return "Kuwo"; };

  static std::unique_ptr<KuwoFileLoader> Create(const KuwoKey& key);
};

}  // namespace parakeet_crypto::decryption::kuwo
