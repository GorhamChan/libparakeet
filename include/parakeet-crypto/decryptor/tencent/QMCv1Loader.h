#pragma once

#include "parakeet-crypto/decryptor/DecryptionStream.h"
#include "parakeet-crypto/misc/QMCFooterParser.h"
#include "parakeet-crypto/misc/QMCKeyDeriver.h"

namespace parakeet_crypto::decryption::tencent {

typedef std::vector<uint8_t> QMCv1Key;

class QMCv1Loader : public DecryptionStream {
 public:
  virtual const std::string GetName() const override { return "QMCv1(static/map)"; };

  static std::unique_ptr<QMCv1Loader> Create(const QMCv1Key& key);
  static std::unique_ptr<QMCv1Loader> Create(std::shared_ptr<misc::tencent::QMCFooterParser> parser);
};

}  // namespace parakeet_crypto::decryption::tencent
