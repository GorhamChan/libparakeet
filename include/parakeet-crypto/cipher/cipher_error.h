#pragma once
#include "cipher.h"

#include <cstddef>
#include <cstdint>
#include <string>

namespace parakeet_crypto::cipher
{

namespace CipherError
{

constexpr CipherErrorCode kSuccess = 0;
constexpr CipherErrorCode kOutputBufferTooSmall = 1;
constexpr CipherErrorCode kIncompleteInputData = 2;

}; // namespace CipherError

/**
 * Get common cipher error message
 *
 * @param error_code Error code ()
 * @return Error message
 */
inline std::string GetCommonCipherErrorMessage(uint32_t error_code)
{
    switch (error_code)
    {
    case CipherError::kSuccess:
        return "OK";

    case CipherError::kOutputBufferTooSmall:
        return "Output buffer too small";

    case CipherError::kIncompleteInputData:
        return "Extra data required before calling Final()";
    }

    return std::string("Error (") + std::to_string(error_code) + std::string(")");
}

} // namespace parakeet_crypto::cipher