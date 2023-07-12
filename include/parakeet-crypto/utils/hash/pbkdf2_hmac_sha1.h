#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <type_traits>
#include <vector>

namespace parakeet_crypto::utils::hash
{

void pbkdf2_hmac_sha1(uint8_t *derived, size_t derived_len,         //
                      const uint8_t *password, size_t password_len, //
                      const uint8_t *salt, size_t salt_len,         //
                      uint32_t iter_count);

template <typename DeriveContainer, typename PasswordContainer, typename SaltContainer,
          typename std::enable_if<!std::is_integral<SaltContainer>::value>::type * = nullptr>
inline void pbkdf2_hmac_sha1(DeriveContainer &&derived, PasswordContainer &&password, SaltContainer &&salt,
                             uint32_t iter_count)
{
    static_assert(sizeof(derived[0]) == 1, "pbkdf2_hmac_sha1: DeriveContainer element should have size of 1");
    static_assert(sizeof(password[0]) == 1, "pbkdf2_hmac_sha1: PasswordContainer element should have size of 1");
    static_assert(sizeof(salt[0]) == 1, "pbkdf2_hmac_sha1: SaltContainer element should have size of 1");

    auto *p_derived = reinterpret_cast<uint8_t *>(derived.data());               // NOLINT(*-reinterpret-cast)
    const auto *p_password = reinterpret_cast<const uint8_t *>(password.data()); // NOLINT(*-reinterpret-cast)
    const auto *p_salt = reinterpret_cast<const uint8_t *>(salt.data());         // NOLINT(*-reinterpret-cast)
    pbkdf2_hmac_sha1(p_derived, derived.size(), p_password, password.size(), p_salt, salt.size(), iter_count);
}

template <typename PasswordContainer, typename SaltContainer>
inline std::vector<uint8_t> pbkdf2_hmac_sha1(PasswordContainer &&password, SaltContainer &&salt, uint32_t iter_count,
                                             size_t derived_len)
{
    std::vector<uint8_t> derived(derived_len);
    pbkdf2_hmac_sha1(derived, password, salt, iter_count);
    return derived;
}

} // namespace parakeet_crypto::utils::hash
