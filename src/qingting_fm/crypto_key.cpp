#include "../utils/endian_helper.h"
#include "../utils/str_helper.hpp"
#include "parakeet-crypto/cipher/aes/aes.h"
#include "parakeet-crypto/utils/base64.h"
#include "qingting_fm.h"

#include <algorithm>
#include <cstdint>
#include <numeric>
#include <string>

namespace parakeet_crypto::qtfm
{

/**
 * Retrive QingTing FM's resource id from the file name or path.
 *
 * @return Resource id, in string format. When failed, returns empty string or invalid string.
 */
inline std::string DecodeFileName(std::string_view name_or_path)
{
    using namespace utils;

    // Strip path, if the name is actually a path...
    auto name = str::getLastItemAfterToken(str::getLastItemAfterToken(name_or_path, '/'), '\\');

    // remove qta suffix
    name = str::stripSuffix(name, ".qta");

    // Since our b64_decode() is capable of handling both base64 and base64-url-safe, we can remove both prefixes,
    // unconditionally. Alternatively, we can just remove all text before the '!' character.
    name = str::stripPrefix(name, ".p!");  // base64 id
    name = str::stripPrefix(name, ".p~!"); // base64 (url-safe) id
    name = Base64DecodeToString(name);

    // Split string by '@', keep the first part
    return str::getFirstItemBeforeToken(name, '@');
}

/**
 * Calculate the hash for the given resource id.
 * The resource id can be retrived by decoding the file name.
 * @return The final hash, used as nonce.
 */
inline int64_t GetHashForNonce(std::string_view resource_id)
{
    return std::accumulate(resource_id.cbegin(), resource_id.cend(), int64_t{0}, [](auto sum, auto chr) {
        sum ^= chr;

        // NOLINTNEXTLINE(*-magic-numbers)
        sum += (sum << 1) + (sum << 4) + (sum << 5) + (sum << 7) + (sum << 8) + (sum << 40);
        return sum;
    });
}

CryptoNonce CreateCryptoNonce(std::string_view filename)
{
    CryptoNonce nonce{};

    auto hash = GetHashForNonce(DecodeFileName(filename));
    WriteBigEndian(nonce.data(), hash);

    return nonce;
}

CryptoCounter CreateCryptoCounter(uint64_t offset)
{
    using AESConfig = cipher::aes::detail::AESConfig<cipher::aes::BLOCK_SIZE::AES_128>;

    CryptoCounter counter{};
    WriteBigEndian(counter.data(), offset / AESConfig::kBlockSize);
    return counter;
}

} // namespace parakeet_crypto::qtfm
