#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace parakeet_crypto::qmc2
{

#pragma pack(push, 4)

struct FooterParseResult
{
    /**
     * @brief Footer size, does not contain any audio data.
     * When decrypting, ignore the last `footer_size` amount of bytes.
     */
    size_t footer_size;

    /**
     * @brief ekey - decrypted
     */
    std::vector<uint8_t> key;
};

#pragma pack(pop)

std::unique_ptr<FooterParseResult> ParseFileFooter(const uint8_t *file_footer, size_t len);

} // namespace parakeet_crypto::qmc2
