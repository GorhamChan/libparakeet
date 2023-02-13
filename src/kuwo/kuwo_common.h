#pragma once
#include "utils/loop_iterator.h"
#include "utils/string_helper.h"

#include <array>
#include <cinttypes>
#include <cstdint>

namespace parakeet_crypto::transformer
{

constexpr size_t kFullKuwoHeaderLen = 0x400; // 1024
static constexpr std::array<uint8_t, 16> kKnownKuwoHeader1 = {'y', 'e', 'e', 'l', 'i', 'o', 'n', '-',
                                                              'k', 'u', 'w', 'o', '-', 't', 'm', 'e'};
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

template <typename Container1, typename Container2>
void SetupKuwoDecryptionKey(Container1 &key_dst, const Container2 &key_src, uint64_t resource_id)
{
    auto rid_str = utils::Format("%" PRIu64, resource_id);
    utils::LoopIterator<char> rid_iter{rid_str, 0};

    auto it_dst = key_dst.begin();
    for (auto it_src = key_src.cbegin(); it_src < key_src.cend(); it_src++)
    {
        *it_dst++ = *it_src ^ static_cast<uint8_t>(rid_iter.GetAndMove());
    }
}

} // namespace parakeet_crypto::transformer
