#pragma once

#include "parakeet-crypto/decryption/DecryptionStream.h"

namespace parakeet_crypto::decryption::tencent {

typedef std::array<uint8_t, 16> JooxSalt;

class JooxFileLoader : public DecryptionStream {
 public:
  virtual const std::string GetName() const override { return "joox"; };

  static std::unique_ptr<JooxFileLoader> Create(const std::string& install_uuid, const JooxSalt& salt);
};

}  // namespace parakeet_crypto::decryption::tencent
