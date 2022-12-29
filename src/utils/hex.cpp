#include "utils/hex.h"
#include "utils/StringHelper.h"

#include <cryptopp/hex.h>

namespace parakeet_crypto::utils {

std::string Hex(const std::span<const uint8_t> data) {
  CryptoPP::HexEncoder encoder(nullptr, false, 2, " ");
  encoder.Put(data.data(), data.size());
  encoder.MessageEnd();

  std::string result(encoder.MaxRetrievable(), 0);
  encoder.Get(reinterpret_cast<uint8_t*>(result.data()), result.size());
  return result;
}

std::string HexCompactLowercase(const std::span<const uint8_t> data) {
  CryptoPP::HexEncoder encoder(nullptr, false, 0, "", "");
  encoder.Put(data.data(), data.size());
  encoder.MessageEnd();

  std::string result(encoder.MaxRetrievable(), 0);
  encoder.Get(reinterpret_cast<uint8_t*>(result.data()), result.size());
  return result;
}

std::vector<uint8_t> UnHex(const std::span<const uint8_t> hex_str) {
  CryptoPP::HexDecoder decoder;
  decoder.Put(hex_str.data(), hex_str.size());
  decoder.MessageEnd();

  std::vector<uint8_t> result(decoder.MaxRetrievable());
  decoder.Get(result.data(), result.size());
  return result;
}

}  // namespace parakeet_crypto::utils
