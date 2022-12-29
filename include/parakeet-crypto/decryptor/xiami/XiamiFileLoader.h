#pragma once

#include "parakeet-crypto/decryptor/StreamDecryptor.h"

namespace parakeet_crypto::decryptor::xiami {

class XiamiFileLoader : public StreamDecryptor {
 public:
  static std::unique_ptr<XiamiFileLoader> Create();
};

}  // namespace parakeet_crypto::decryptor::xiami
