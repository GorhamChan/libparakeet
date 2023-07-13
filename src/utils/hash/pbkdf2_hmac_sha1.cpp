#include "parakeet-crypto/utils/hash/pbkdf2_hmac_sha1.h"
#include "parakeet-crypto/utils/hash/hmac_sha1.h"
#include "parakeet-crypto/utils/hash/sha1.h"
#include "utils/endian_helper.h"

#include <algorithm>
#include <cstdint>
#include <vector>

// Implemented according to rfc2898.

namespace parakeet_crypto::utils::hash
{

void pbkdf2_hmac_sha1(uint8_t *derived, size_t derived_len,         //
                      const uint8_t *password, size_t password_len, //
                      const uint8_t *salt, size_t salt_len,         //
                      uint32_t iter_count)
{
    // cache context
    hmac_sha1_ctx prf_ctx_cache{};
    hmac_sha1_init(&prf_ctx_cache, password, password_len);

    // Copy extra 4 bytes to avoid re-allocate
    std::array<uint8_t, sizeof(uint32_t)> block_id_buff{};

    // Define pre-allocated buffers
    std::array<uint8_t, kSHA1DigestSize> digest_hash{};
    std::array<uint8_t, kSHA1DigestSize> u_current{};

    auto do_derive_block = [&](uint32_t block_id) {
        /* U_1 */ {
            WriteBigEndian(block_id_buff.data(), block_id);

            hmac_sha1_ctx prf_ctx{prf_ctx_cache};
            hmac_sha1_update(&prf_ctx, salt, salt_len);
            hmac_sha1_update(&prf_ctx, block_id_buff.data(), block_id_buff.size());
            hmac_sha1_final(&prf_ctx, u_current.data()); // u_1
            std::copy(u_current.cbegin(), u_current.cend(), digest_hash.begin());
        }

        // U_2 ... U_c
        for (uint32_t _i = 1; _i < iter_count; _i++)
        {
            hmac_sha1_ctx prf_ctx{prf_ctx_cache};
            hmac_sha1_update(&prf_ctx, u_current.data(), u_current.size()); // u_{i-1}
            hmac_sha1_final(&prf_ctx, u_current.data());                    // u_{i}

            const auto *prev_it = u_current.data();
            for (auto &value : digest_hash)
            {
                value ^= *prev_it++;
            }
        }
    };

    // The number of blocks (floor) + 1.
    const auto full_block_count_off1 = static_cast<uint32_t>(derived_len / kSHA1DigestSize) + 1;
    auto *p_derived = derived;
    for (uint32_t i = 1; i < full_block_count_off1; i++)
    {
        do_derive_block(i);
        std::copy(digest_hash.cbegin(), digest_hash.cend(), p_derived);
        p_derived += kSHA1DigestSize;
    }

    // Not a full block, derive and take the first x bytes.
    if (auto last_block_elements = derived_len % kSHA1DigestSize; last_block_elements != 0)
    {
        do_derive_block(full_block_count_off1);
        std::copy_n(digest_hash.cbegin(), last_block_elements, p_derived);
    }
}

} // namespace parakeet_crypto::utils::hash
