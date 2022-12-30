#pragma once

#include "parakeet-crypto/decryptor/StreamDecryptor.h"
#include "parakeet-crypto/misc/QMCFooterParser.h"
#include "parakeet-crypto/misc/QMCKeyDeriver.h"

namespace parakeet_crypto::decryptor::tencent {

using QMCv1Key = std::vector<uint8_t>;

class QMCv1Loader : public StreamDecryptor {
   public:
    virtual std::string GetName() const override { return "QMCv1(static/map)"; };

    static std::unique_ptr<QMCv1Loader> Create(const QMCv1Key& key);
    static std::unique_ptr<QMCv1Loader> Create(std::shared_ptr<misc::tencent::QMCFooterParser> parser);
};

}  // namespace parakeet_crypto::decryptor::tencent
