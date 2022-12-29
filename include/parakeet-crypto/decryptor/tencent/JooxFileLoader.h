#pragma once

#include "parakeet-crypto/decryptor/StreamDecryptor.h"

namespace parakeet_crypto::decryptor::tencent {

typedef std::array<uint8_t, 16> JooxSalt;

class JooxFileLoader : public StreamDecryptor {
 public:
  virtual const std::string GetName() const override { return "joox"; };

  static std::unique_ptr<JooxFileLoader> Create(const std::string& install_uuid, const JooxSalt& salt);
};

}  // namespace parakeet_crypto::decryptor::tencent
