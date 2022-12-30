#pragma once

#include "parakeet-crypto/decryptor/StreamDecryptor.h"
#include "parakeet-crypto/misc/QMCFooterParser.h"
#include "parakeet-crypto/misc/QMCKeyDeriver.h"

namespace parakeet_crypto::decryptor::tencent {

class QMCv2Loader : public StreamDecryptor {
   public:
    virtual const std::string GetName() const override { return "QMCv2(RC4)"; };

    static std::unique_ptr<QMCv2Loader> Create(std::shared_ptr<misc::tencent::QMCFooterParser> parser);
};

}  // namespace parakeet_crypto::decryptor::tencent
