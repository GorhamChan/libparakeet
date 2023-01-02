#pragma once

#include "parakeet-crypto/decryptor/StreamDecryptor.h"

#include <memory>

namespace parakeet_crypto::decryptor::xiami {

class XiamiFileLoader : public StreamDecryptor {
   public:
    static std::unique_ptr<XiamiFileLoader> Create();
};

}  // namespace parakeet_crypto::decryptor::xiami
