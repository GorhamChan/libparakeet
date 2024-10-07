#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace parakeet_crypto::cipher
{

// 0 for success; code <= 1023 is reserved for common errors
// For common error constants, include "cipher_error.h".
using CipherErrorCode = uint32_t;

class Cipher
{
  public:
    virtual ~Cipher() = default;

    /**
     * Update the block cipher with input data.
     *
     * @param output Pointer to the output buffer. It should normally be equal or larger than n bytes.
     * @param n_output Pointer to the number of bytes available in the output buffer. It will be updated with the
     *                 number of bytes written to the output buffer.
     * @param input Pointer to the input buffer
     * @param n Number of bytes to process
     * @return Error code. 0 for success, otherwise an error code.
     */
    [[nodiscard]] virtual CipherErrorCode Update(uint8_t *output, size_t &n_output, const uint8_t *input, size_t n) = 0;

    /**
     * Finalize the block cipher.
     * @param output Pointer to the output buffer. Sometimes it can be nullptr.
     * @param n_output Pointer to the number of bytes available in the output buffer. It will be updated with the
     *                 number of bytes written to the output buffer.
     * @return Error code. 0 for success, otherwise an error code.
     */
    [[nodiscard]] virtual CipherErrorCode Final(uint8_t *output, size_t &n_output) = 0;
};

} // namespace parakeet_crypto::cipher
