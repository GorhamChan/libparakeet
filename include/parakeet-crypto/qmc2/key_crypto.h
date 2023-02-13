#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace parakeet_crypto::qmc2
{

enum class KeyVersion
{
    VERSION_1 = 1,
    VERSION_2 = 2,
};

class IKeyCrypto
{
  public:
    virtual ~IKeyCrypto() = default;

    virtual std::vector<uint8_t> Decrypt(const uint8_t *key, size_t len) = 0;
    virtual std::vector<uint8_t> Encrypt(const uint8_t *key, size_t len, KeyVersion version) = 0;
};

static constexpr size_t kEncV2KeyLen = 16;
std::unique_ptr<IKeyCrypto> CreateKeyCrypto(uint8_t seed, const uint8_t *enc_v2_key_1, const uint8_t *enc_v2_key_2);

} // namespace parakeet_crypto::qmc2
