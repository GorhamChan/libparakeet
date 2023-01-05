#pragma once

#include <climits>
#include <cstdint>
#include <cstdlib>

#include <bit>
#include <concepts>
#include <type_traits>

#if _MSC_VER
#ifndef __builtin_bswap64
#define __builtin_bswap64 _byteswap_uint64
#define __builtin_bswap32 _byteswap_ulong
#define __builtin_bswap16 _byteswap_ushort
#endif  // #ifndef __builtin_bswap64
#elif (__clang__ || __GNUG__)
// OK - clang / g++ should have this already.
#elif !defined(__has_builtin) || !__has_builtin(__builtin_bswap64)
#error __builtin_bswap_xx macro/methods missing.
#endif

namespace parakeet_crypto {

namespace detail {

constexpr bool is_le = std::endian::native == std::endian::little;
constexpr bool is_be = std::endian::native == std::endian::big;

template <std::integral T>
constexpr T swap_bytes(T input) {
    if constexpr (std::is_same_v<std::make_unsigned_t<T>, uint64_t>) {
        return T(__builtin_bswap64(uint64_t(input)));
    } else if constexpr (std::is_same_v<std::make_unsigned_t<T>, uint32_t>) {
        return T(__builtin_bswap32(uint32_t(input)));
    } else if constexpr (std::is_same_v<std::make_unsigned_t<T>, uint16_t>) {
        return T(__builtin_bswap16(uint16_t(input)));
    } else {
        static_assert(std::is_same_v<std::make_unsigned_t<T>, uint8_t>, "unsupported type for swap_bytes");
        return input;  // uint8_t -- no conversion required
    }
}

}  // namespace detail

////////////////////////////////////////////////////////////////////////////////
// Simple inline conversion
// LE <--> LE: noop
// BE <--> BE: noop
// Otherwise: swap

template <std::integral T>
constexpr T SwapHostToLittleEndian(T input) {
    if constexpr (detail::is_le) {
        return input;
    } else {
        return detail::swap_bytes(input);
    }
}

template <std::integral T>
constexpr T SwapHostToBigEndian(T input) {
    if constexpr (detail::is_be) {
        return input;
    } else {
        return detail::swap_bytes(input);
    }
}

template <std::integral T>
constexpr T SwapLittleEndianToHost(T input) {
    if constexpr (detail::is_le) {
        return input;
    } else {
        return detail::swap_bytes(input);
    }
}

template <std::integral T>
constexpr T SwapBigEndianToHost(T input) {
    if constexpr (detail::is_be) {
        return input;
    } else {
        return detail::swap_bytes(input);
    }
}

////////////////////////////////////////////////////////////////////////////////
// Pointer access - Read

template <std::integral A>
inline A ReadBigEndian(const uint8_t* ptr) {
    using UA = std::make_unsigned_t<A>;

    UA result = UA{0};
    for (const auto* const p_end = ptr + sizeof(A); ptr != p_end; ptr++) {
        result <<= CHAR_BIT;
        result |= UA{*ptr};
    }

    return static_cast<A>(result);
}

template <std::integral A>
inline A ReadLittleEndian(const uint8_t* ptr) {
    return detail::swap_bytes(ReadBigEndian<A>(ptr));
}

////////////////////////////////////////////////////////////////////////////////
// Pointer access - Write

template <std::integral A>
inline void WriteLittleEndian(uint8_t* ptr, A value) {
    using UA = std::make_unsigned_t<A>;

    auto temp_value = static_cast<UA>(value);
    for (const auto* p_end = ptr + sizeof(A); ptr != p_end; ptr++) {
        *ptr = static_cast<uint8_t>(temp_value);
        temp_value >>= CHAR_BIT;
    }
}

template <std::integral A>
inline void WriteBigEndian(uint8_t* ptr, A value) {
    WriteLittleEndian<A>(ptr, detail::swap_bytes(value));
}

}  // namespace parakeet_crypto
