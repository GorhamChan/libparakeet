#pragma once

#include "parakeet-crypto/decryptor/StreamDecryptor.h"

namespace parakeet_crypto::decryptor::xiami {

class XiamiFileLoader : public StreamDecryptor {
 public:
  virtual const std::string GetName() const override { return "Xiami"; };
  static std::unique_ptr<XiamiFileLoader> Create();
};

}  // namespace parakeet_crypto::decryptor::xiami
