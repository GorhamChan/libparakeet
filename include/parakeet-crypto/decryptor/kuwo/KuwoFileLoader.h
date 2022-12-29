#pragma once

#include "parakeet-crypto/decryptor/StreamDecryptor.h"

namespace parakeet_crypto::decryptor::kuwo {

constexpr std::size_t kKuwoDecryptionKeySize = 0x20;
typedef std::array<uint8_t, kKuwoDecryptionKeySize> KuwoKey;

class KuwoFileLoader : public StreamDecryptor {
 public:
  virtual const std::string GetName() const override { return "Kuwo"; };

  static std::unique_ptr<KuwoFileLoader> Create(const KuwoKey& key);
};

}  // namespace parakeet_crypto::decryptor::kuwo
