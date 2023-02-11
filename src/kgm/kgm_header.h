#pragma once
#include "parakeet-crypto/IStream.h"
#include "utils/endian_helper.h"
#include <cstdint>
#include <optional>

namespace parakeet_crypto::kgm
{

#pragma pack(push, 1)
// NOLINTBEGIN(*-magic-numbers, *-avoid-c-arrays)
struct FileHeader
{
    // Offset: 0x00
    uint8_t magic_header[16];
    // Offset: 0x10
    uint32_t offset_to_data;
    uint32_t crypto_version;
    uint32_t key_slot;
    // Offset: 0x1C
    uint8_t decryption_test_data[16];
    // Offset: 0x2C
    uint8_t file_key[16];
};
// NOLINTEND(*-magic-numbers, *-avoid-c-arrays)
#pragma pack(pop)

inline std::optional<FileHeader> FileHeaderFromStream(IReadSeekable *stream)
{
    FileHeader header{};
    if (!stream->ReadExact(reinterpret_cast<uint8_t *>(&header), // NOLINT(*-reinterpret-cast)
                           sizeof(header)))
    {
        return {};
    }

    // Fix endian; should be noop in x86-64
    header.crypto_version = SwapLittleEndianToHost(header.crypto_version);
    header.key_slot = SwapLittleEndianToHost(header.key_slot);
    header.offset_to_data = SwapLittleEndianToHost(header.offset_to_data);

    return header;
}

} // namespace parakeet_crypto::kgm
