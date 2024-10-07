#pragma once
#include <array>
#include <cstddef>
#include <string_view>

namespace parakeet_crypto::qtfm
{

constexpr size_t kDeviceSecretKeySize = 16;
using DeviceSecretKey = std::array<uint8_t, kDeviceSecretKeySize>;

constexpr size_t kCryptoNonceSize = 8;
using CryptoNonce = std::array<uint8_t, kCryptoNonceSize>;

constexpr size_t kCryptoCounterSize = 8;
using CryptoCounter = std::array<uint8_t, kCryptoCounterSize>;

constexpr size_t kCryptoIVSize = 16;
using CryptoIV = std::array<uint8_t, kCryptoIVSize>;

/**
 * @brief Create the secret key based on the device information
 *
 * @param product         `Build.PRODUCT`
 * @param device          `Build.DEVICE`
 * @param manufacturer    `Build.MANUFACTURER`
 * @param brand           `Build.BRAND`
 * @param board           `Build.BOARD`
 * @param model           `Build.MODEL`
 * @example
 * To get the device information, run the following:
 *
 *     import android.os.Build;
 *
 *     var DeviceInfo = { Build.PRODUCT
 *                      , Build.DEVICE
 *                      , Build.MANUFACTURER
 *                      , Build.BRAND
 *                      , Build.BOARD
 *                      , Build.MODEL         };
 */
DeviceSecretKey CreateDeviceSecretKey(std::string_view product, std::string_view device, std::string_view manufacturer,
                                      std::string_view brand, std::string_view board, std::string_view model);

} // namespace parakeet_crypto::qtfm
