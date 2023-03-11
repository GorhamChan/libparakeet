#include "qrc_des.h"
#include "int_helper.h"
#include "qrc/int_helper.h"
#include "qrc_des_data.h"

#include "utils/endian_helper.h"
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <numeric>

namespace parakeet_crypto::qrc
{

inline uint64_t sbox_transform(uint64_t state)
{
    constexpr std::array<uint8_t, 8> kLargeStateShifts = {26, 20, 14, 8, 58, 52, 46, 40};
    constexpr uint8_t kMaskSelectLast6Bit = 0b111111;

    auto large_state_it = kLargeStateShifts.cbegin(); // NOLINT(readability-qualified-auto)
    return std::accumulate(data::kSBoxes.cbegin(), data::kSBoxes.cend(), uint32_t{0},
                           [&](const auto &next, const auto &sbox) {
                               auto sbox_idx = (state >> *large_state_it++) & kMaskSelectLast6Bit;
                               return (next << 4) | sbox[sbox_idx];
                           });
}

inline uint64_t des_crypt_proc(uint64_t state, uint64_t key)
{
    // Expansion Permutation
    auto state_hi32 = int_helper::u64_get_hi32(state);
    auto state_lo32 = int_helper::u64_get_lo32(state);

    state = int_helper::map_u64(int_helper::make_u64(state_hi32, state_hi32), data::kKeyExpansionTable);
    state ^= key;

    auto next_lo32 = sbox_transform(state);
    next_lo32 = int_helper::map_u32_bits(next_lo32, data::kPBox);
    next_lo32 ^= state_lo32;

    // make u64, then swap
    //   => make reverted u64
    // return swap_u64_side(int_helper::make_u64(state_hi32, next_lo32));
    return int_helper::make_u64(next_lo32, state_hi32); // NOLINT(readability-suspicious-call-argument)
}

inline constexpr uint64_t IP(uint64_t data)
{
    return int_helper::map_u64(data, data::kIpTable);
}

inline constexpr uint64_t IPInv(uint64_t state)
{
    return int_helper::map_u64(state, data::kIpInvTable);
}

void QRC_DES::setup_key(const char *key_str)
{
    auto key = parakeet_crypto::ReadLittleEndian<uint64_t>(key_str);

    auto param = int_helper::map_u64(key, data::kKeyPermutationTable);
    auto param_c = int_helper::u64_get_lo32(param);
    auto param_d = int_helper::u64_get_hi32(param);

    auto update_param = [](uint32_t &value, uint8_t shift_left) {
        // NOLINTBEGIN (*-magic-numbers)
        auto shift_right = 28 - shift_left;
        value = (value << shift_left) | (value >> shift_right) & 0xFFFFFFF0;
        // NOLINTEND (*-magic-numbers)
    };

    auto subkey_it = subkeys.begin(); // NOLINT(readability-qualified-auto)
    std::for_each(data::key_rnd_shift.begin(), data::key_rnd_shift.end(), [&](const auto &shift_left) {
        update_param(param_c, shift_left);
        update_param(param_d, shift_left);

        auto key = int_helper::make_u64(param_d, param_c);
        *subkey_it++ = int_helper::map_u64(key, data::kKeyCompressionTable);
    });
}

uint64_t QRC_DES::des_crypt_block(uint64_t data, bool is_decrypt) const
{
    // Initial permutation
    auto state = IP(data);

    if (is_decrypt)
    {
        state = std::accumulate(subkeys.crbegin(), subkeys.crend(), state, des_crypt_proc);
    }
    else
    {
        state = std::accumulate(subkeys.cbegin(), subkeys.cend(), state, des_crypt_proc);
    }

    // Swap data hi32/lo32
    state = int_helper::swap_u64_side(state);

    // Final permutation
    state = IPInv(state);

    return state;
}

} // namespace parakeet_crypto::qrc
