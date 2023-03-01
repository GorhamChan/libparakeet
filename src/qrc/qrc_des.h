#pragma once
#include "utils/endian_helper.h"
#include <array>
#include <cstddef>
#include <cstdint>

namespace parakeet_crypto::qrc
{

// NOLINTBEGIN(*-magic-numbers)
using QRC_DES_Subkeys = std::array<uint64_t, 16>;

class QRC_DES
{
  private:
    // 8*16 = 128 byte
    QRC_DES_Subkeys subkeys{0};

  public:
    QRC_DES() = default;
    QRC_DES(const char *key)
    {
        setup_key(key);
    }

    void setup_key(const char *key_str);
    void setup_key(const uint8_t *key)
    {
        setup_key(reinterpret_cast<const char *>(key)); // NOLINT(*reinterpret-cast)
    }

    [[nodiscard]] uint64_t des_crypt_block(uint64_t data, bool is_decrypt) const;
    void des_crypt_block(uint8_t *p_block, bool is_decrypt) const
    {
        auto block = ReadLittleEndian<uint64_t>(p_block);
        auto result = des_crypt_block(block, is_decrypt);
        WriteLittleEndian(p_block, result);
    }
    bool des_crypt(uint8_t *data, size_t n, bool is_decrypt) const
    {
        if (n % 8 != 0)
        {
            return false;
        }

        while (n > 0)
        {
            des_crypt_block(data, is_decrypt);
            data += 8;
            n -= 8;
        }
        return true;
    }
};
// NOLINTEND(*-magic-numbers)

} // namespace parakeet_crypto::qrc
