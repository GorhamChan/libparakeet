#include <parakeet-crypto/utils/tc_tea.h>
#include <tc_tea/tc_tea.h>

#include <cstdint>
#include <vector>

namespace parakeet_crypto::utils
{

std::vector<uint8_t> TeaEncrypt(const uint8_t *data, size_t data_len, const uint8_t *key)
{
    auto cipher_len = tc_tea::CBC_GetEncryptedSize(data_len);
    auto result = std::vector<uint8_t>(cipher_len);

    if (tc_tea::CBC_Encrypt(result.data(), &cipher_len, data, data_len, key))
    {
        result.resize(cipher_len);
        return result;
    }

    return {};
}

std::vector<uint8_t> TeaDecrypt(const uint8_t *data, size_t data_len, const uint8_t *key)
{
    auto plain_len = data_len;
    std::vector<uint8_t> plain(plain_len);
    if (tc_tea::CBC_Decrypt(plain.data(), &plain_len, data, plain_len, key))
    {
        plain.resize(plain_len);
        return plain;
    }
    return {};
}

} // namespace parakeet_crypto::utils
