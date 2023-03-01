#include "qrc_des.h"
#include "int_helper.h"
#include "qrc_des_data.h"

#include "utils/endian_helper.h"
#include <cassert>
#include <cstdint>

namespace parakeet_crypto::qrc
{

inline uint64_t des_crypt_proc(const QRC_DES_Subkeys &subkeys, uint64_t state, int key_idx)
{
    // Expantion Permutation
    const std::array<uint8_t, 24> kKeyExpansionTablePart1 = {32, 1, 2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
                                                             8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17};
    const std::array<uint8_t, 24> kKeyExpansionTablePart2 = {16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
                                                             24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1};

    auto state_hi32 = int_helper::u64_get_hi32(state);
    auto state_lo32 = int_helper::u64_get_lo32(state);

    auto t1 = int_helper::map_u32_bits(state_hi32, kKeyExpansionTablePart1); // NOLINT(readability-identifier-length)
    auto t2 = int_helper::map_u32_bits(state_hi32, kKeyExpansionTablePart2); // NOLINT(readability-identifier-length)
    state = int_helper::make_u64(t2, t1) ^ subkeys[key_idx];

    // NOLINTBEGIN (*-magic-numbers)
    const std::array<uint8_t, 8> large_state{
        static_cast<uint8_t>((state >> 26) & uint8_t{0x3F}), //
        static_cast<uint8_t>((state >> 20) & uint8_t{0x3F}), //
        static_cast<uint8_t>((state >> 14) & uint8_t{0x3F}), //
        static_cast<uint8_t>((state >> 8) & uint8_t{0x3F}),  //
        static_cast<uint8_t>((state >> 58) & uint8_t{0x3F}), //
        static_cast<uint8_t>((state >> 52) & uint8_t{0x3F}), //
        static_cast<uint8_t>((state >> 46) & uint8_t{0x3F}), //
        static_cast<uint8_t>((state >> 40) & uint8_t{0x3F}), //
    };
    // NOLINTEND (*-magic-numbers)

    // S-Box Permutation
    uint32_t next_lo32 = {0};
    for (int i = 0; i < 8; i++) // NOLINT (*-magic-numbers)
    {
        next_lo32 = (next_lo32 << 4) | data::g_sboxes[i][large_state[i]];
    }

    next_lo32 = int_helper::map_u32_bits(next_lo32, data::PBox);
    next_lo32 ^= state_lo32;

    // make u64, then swap
    //   => make reverted u64
    // return swap_u64_side(int_helper::make_u64(state_hi32, next_lo32));
    return int_helper::make_u64(next_lo32, state_hi32); // NOLINT(readability-suspicious-call-argument)
}

inline constexpr uint64_t IP(uint64_t data)
{
    return int_helper::map_u64_bits(data, data::kIpTable);
}

inline constexpr uint64_t IPInv(uint64_t state)
{
    return int_helper::map_u64_bits(state, data::kIpInvTable);
}

void QRC_DES::setup_key(const char *key_str)
{
    auto key = parakeet_crypto::ReadLittleEndian<uint64_t>(key_str);

    auto param_c = int_helper::map_u64_to_u32_bits(key, data::key_perm_c);
    auto param_d = int_helper::map_u64_to_u32_bits(key, data::key_perm_d);

    // NOLINTBEGIN (*-magic-numbers)
    for (int i = 0; i < 16; i++)
    {
        auto shift_left = data::key_rnd_shift[i];
        auto shift_right = 28 - shift_left;
        param_c = (param_c << shift_left) | ((param_c >> shift_right) & 0xFFFFFFF0); // rotate 28 bit int
        param_d = (param_d << shift_left) | ((param_d >> shift_right) & 0xFFFFFFF0);

        for (int j = 0; j < 24; j++)
        {
            uint32_t key_lo32 = int_helper::map_u32_bits(param_c, data::kKeyCompressionTablePart1, -1);
            uint32_t key_hi32 = int_helper::map_u32_bits(param_d, data::kKeyCompressionTablePart2, -28);
            subkeys[i] = int_helper::make_u64(key_hi32, key_lo32);
        }
    }
    // NOLINTEND (*-magic-numbers)
}

uint64_t QRC_DES::des_crypt_block(uint64_t data, bool is_decrypt) const
{
    // Initial permutation
    auto state = IP(data);

    if (is_decrypt)
    {
        for (int i = 15; i >= 0; --i)
        {
            state = des_crypt_proc(subkeys, state, i);
        }
    }
    else
    {
        for (int i = 0; i < 16; ++i)
        {
            state = des_crypt_proc(subkeys, state, i);
        }
    }

    // Swap data hi32/lo32
    state = int_helper::swap_u64_side(state);

    // Final permutation
    state = IPInv(state);

    return state;
}

} // namespace parakeet_crypto::qrc
