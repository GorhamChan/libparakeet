#pragma once
#include "parakeet-crypto/qingting_fm/device_key.h"

#include <cstdint>
#include <utility>

namespace parakeet_crypto::qtfm
{

/**
 * Create AES/CRT Nonce from given filename.
 * @return First half of the IV to initialize AES/CRT/NoPadding. Second half is "offset / block_size" in BigEndian.
 */
CryptoNonce CreateCryptoNonce(std::string_view filename);

/**
 * Create AES/CRT Counter from given offset.
 * @return Counter bytes, in BigEndian.
 */
CryptoCounter CreateCryptoCounter(uint64_t offset);

/**
 * Generate AES/CRT IV from given filename and offset.
 * @param filename Filename, e.g. ".p~!123456ABCD.qta"
 * @param offset Offset of the file, e.g. 0
 * @return Generated IV.
 */
inline CryptoIV CreateCryptoIV(std::string_view filename, uint64_t offset)
{
    auto nonce = CreateCryptoNonce(filename);
    auto counter = CreateCryptoCounter(offset);

    CryptoIV result{};
    std::copy(nonce.cbegin(), nonce.cend(), result.begin());
    std::copy(counter.cbegin(), counter.cend(), result.begin() + nonce.size());
    return result;
}

}; // namespace parakeet_crypto::qtfm
