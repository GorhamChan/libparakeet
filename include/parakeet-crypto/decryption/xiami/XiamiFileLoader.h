#pragma once

#include "parakeet-crypto/decryption/DecryptionStream.h"

namespace parakeet_crypto::decryption::xiami {

class XiamiFileLoader : public DecryptionStream {
 public:
  virtual const std::string GetName() const override { return "Xiami"; };
  static std::unique_ptr<XiamiFileLoader> Create();
};

}  // namespace parakeet_crypto::decryption::xiami
