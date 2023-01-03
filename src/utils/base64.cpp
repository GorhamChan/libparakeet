#include "utils/base64.h"
#include "utils/StringHelper.h"

#include <cryptopp/base64.h>

namespace parakeet_crypto::utils {

std::vector<uint8_t> Base64Decode(const std::span<const uint8_t> input) {
    CryptoPP::Base64Decoder decoder;
    decoder.Put(input.data(), input.size());
    decoder.MessageEnd();

    std::vector<uint8_t> result(decoder.MaxRetrievable());
    decoder.Get(result.data(), result.size());
    return result;
}

std::string Base64Encode(const std::span<const uint8_t> input) {
    CryptoPP::Base64Encoder encoder(nullptr, false);
    encoder.Put(input.data(), input.size());
    encoder.MessageEnd();

    std::string result(encoder.MaxRetrievable(), 0);
    encoder.Get(reinterpret_cast<uint8_t*>(result.data()), result.size());
    return result;
}

}  // namespace parakeet_crypto::utils
