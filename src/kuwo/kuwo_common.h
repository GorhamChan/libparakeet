#pragma once
#include "utils/string_helper.h"

#include <array>
#include <cinttypes>
#include <cstdint>

namespace parakeet_crypto::transformer
{

constexpr size_t kFullKuwoHeaderLen = 0x400; // 1024
static constexpr std::array<uint8_t, 16> kKnownKuwoHeader1 = {'y', 'e', 'e', 'l', 'i', 'o', 'n', '-',
                                                              'k', 'u', 'w', 'o', 0,   0,   0,   0};
static constexpr std::array<uint8_t, 16> kKnownKuwoHeader2 = {'y', 'e', 'e', 'l', 'i', 'o', 'n', '-',
                                                              'k', 'u', 'w', 'o', 0,   0,   0,   0};

#pragma pack(push, 4)
// NOLINTBEGIN(*-magic-numbers, *-avoid-c-arrays)
struct KuwoHeader
{
    // Offset: 0x00
    uint8_t header[16];
    // Offset: 0x10
    uint64_t _unknown_1;
    uint64_t resource_id;
};

union KuwoHeaderUnion {
    KuwoHeader as_header;
    uint8_t as_bytes[sizeof(KuwoHeader)];
};
// NOLINTEND(*-magic-numbers, *-avoid-c-arrays)
#pragma pack(pop)

template <typename Iterator>
void SetupKuwoDecryptionKey(uint64_t resource_id, Iterator decryption_key, Iterator decryption_key_end)
{
    auto rid_str = utils::Format("%" PRIu64, resource_id);
    auto p_rid_str = rid_str.begin();
    auto p_rid_str_end = rid_str.end();

    while (decryption_key < decryption_key_end)
    {
        *decryption_key++ ^= *p_rid_str++;

        if (p_rid_str == p_rid_str_end)
        {
            p_rid_str = rid_str.begin();
        }
    }
}

} // namespace parakeet_crypto::transformer
