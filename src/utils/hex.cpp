#include "utils/hex.h"

#include <cryptopp/hex.h>

namespace parakeet_crypto::utils {

std::string Hex(const uint8_t* data, size_t len, bool upper, bool add_space) {
    CryptoPP::HexEncoder encoder(nullptr, upper, add_space ? 2 : 0, add_space ? " " : "");
    encoder.Put(data, len);
    encoder.MessageEnd();

    std::string result(encoder.MaxRetrievable(), 0);
    encoder.Get(reinterpret_cast<uint8_t*>(result.data()), result.size());  // NOLINT(*-type-reinterpret-cast)
    return result;
}

std::vector<uint8_t> UnHex(const uint8_t* hex_str, size_t len) {
    CryptoPP::HexDecoder decoder;
    decoder.Put(hex_str, len);
    decoder.MessageEnd();

    std::vector<uint8_t> result(decoder.MaxRetrievable());
    decoder.Get(result.data(), result.size());
    return result;
}

}  // namespace parakeet_crypto::utils
