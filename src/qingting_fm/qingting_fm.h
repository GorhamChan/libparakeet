#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <utility>

namespace parakeet_crypto::qingting_fm
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

}; // namespace parakeet_crypto::qingting_fm
