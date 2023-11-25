#include "../utils/endian_helper.h"
#include "../utils/str_helper.hpp"
#include "parakeet-crypto/utils/aes.h"
#include "parakeet-crypto/utils/base64.h"
#include "qingting_fm.h"

#include <algorithm>
#include <cstdint>
#include <numeric>
#include <string>

namespace parakeet_crypto::qingting_fm
{

inline std::string DecodeFileName(std::string_view name_or_path)
{
    using namespace utils;

    // Strip path, if the name is actually a path...
    auto name = str::getLastItemAfterToken(str::getLastItemAfterToken(name_or_path, '/'), '\\');

    // remove qta suffix
    name = str::stripSuffix(name, ".qta");

    if (name.size() > 3)
    {
        if (name[2] == '!')
        {
            name = str::stripPrefix(name, ".p!"); // base64
        }
        else
        {
            name = str::stripPrefix(name, ".p~!"); // base64 (url-safe)
        }
    }

    name = Base64DecodeToString(name);
    return str::getFirstItemBeforeToken(name, '@');
}

inline int64_t GetHashForNonce(std::string_view name)
{
    constexpr std::array<int, 6> kShifts = {1, 4, 5, 7, 8, 40};

    int64_t result = 0;
    for (auto chr : name)
    {
        result ^= chr;
        // NOLINTNEXTLINE(*-magic-numbers)
        result += (result << 1) + (result << 4) + (result << 5) + (result << 7) + (result << 8) + (result << 40);
    }

    return result;
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
    using namespace utils::aes;
    using AESConfig = utils::aes::detail::AESConfig<BLOCK_SIZE::AES_128>;

    CryptoCounter counter{};
    WriteBigEndian(counter.data(), offset / AESConfig::kBlockSize);
    return counter;
}

} // namespace parakeet_crypto::qingting_fm
