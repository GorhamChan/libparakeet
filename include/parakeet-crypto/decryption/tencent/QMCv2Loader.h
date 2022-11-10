#pragma once

#include "parakeet-crypto/decryption/DecryptionStream.h"
#include "parakeet-crypto/misc/QMCFooterParser.h"
#include "parakeet-crypto/misc/QMCKeyDeriver.h"

namespace parakeet_crypto::decryption::tencent {

class QMCv2Loader : public DecryptionStream {
 public:
  virtual const std::string GetName() const override { return "QMCv2(RC4)"; };

  static std::unique_ptr<QMCv2Loader> Create(std::shared_ptr<misc::tencent::QMCFooterParser> parser);
};

}  // namespace parakeet_crypto::decryption::tencent
