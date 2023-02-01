#include "utils/base64.h"
#include "utils/StringHelper.h"

#include <cryptopp/base64.h>

namespace parakeet_crypto::utils {

std::vector<uint8_t> Base64Encode(const uint8_t* input, size_t len) {
    CryptoPP::Base64Encoder encoder(nullptr, false);
    encoder.Put(input, len);
    encoder.MessageEnd();

    std::vector<uint8_t> result(encoder.MaxRetrievable(), 0);
    encoder.Get(result.data(), result.size());
    return result;
}

std::vector<uint8_t> Base64Decode(const uint8_t* input, size_t len) {
    CryptoPP::Base64Decoder decoder;
    decoder.Put(input, len);
    decoder.MessageEnd();

    std::vector<uint8_t> result(decoder.MaxRetrievable());
    decoder.Get(result.data(), result.size());
    return result;
}

}  // namespace parakeet_crypto::utils
