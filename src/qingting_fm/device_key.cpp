#include "parakeet-crypto/utils/hex.h"
#include "qingting_fm.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <numeric>
#include <string>
#include <vector>

#include "../utils/endian_helper.h"

namespace parakeet_crypto::qingting_fm
{

/**
 * A simple implementation of Java String#hashCode
 *
 * @see https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/lang/String.html#hashCode()
 */
int32_t LJava_String_hashCode(std::string_view &str)
{
    int32_t hash = 0;
    for (char chr : str)
    {
        // NOLINTNEXTLINE(*-magic-numbers)
        hash = hash * 31 + chr;
    }
    return hash;
}

constexpr std::array<uint8_t, kDeviceSecretKeySize> g_device_secret_salt = {
    0x26, 0x2b, 0x2b, 0x12, 0x11, 0x12, 0x14, 0x0a, 0x08, 0x00, 0x08, 0x0a, 0x14, 0x12, 0x11, 0x12};

DeviceSecretKey CreateDeviceSecretKey(std::string_view product, std::string_view device, std::string_view manufacturer,
                                      std::string_view brand, std::string_view board, std::string_view model)
{
    auto device_id_hash_code = LJava_String_hashCode(product) + LJava_String_hashCode(device) +
                               LJava_String_hashCode(manufacturer) + LJava_String_hashCode(brand) +
                               LJava_String_hashCode(board) + LJava_String_hashCode(model);

    auto device_id_hex = utils::IntToHexString(device_id_hash_code, false);

    const auto *p_salt = g_device_secret_salt.data();

    DeviceSecretKey device_key{};
    std::copy(device_id_hex.cbegin(), device_id_hex.cend(), device_key.begin());
    std::transform(device_key.begin(), device_key.end(), device_key.begin(),
                   [&](auto byte) { return byte + *p_salt++; });
    return device_key;
}

} // namespace parakeet_crypto::qingting_fm
