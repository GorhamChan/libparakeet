#pragma once

#include "parakeet-crypto/endian.h"

namespace parakeet_crypto::utils {

inline int32_t ParseID3SyncSafeInt(const uint8_t* p) {
  auto raw = parakeet_crypto::ReadBigEndian<uint32_t>(p);

  // Sync safe int should use only lower 7-bits of each byte.
  if ((raw & 0x80808080u) != 0) {
    return 0;
  }

  return ((raw & 0x7F00'0000) >> 3) | ((raw & 0x007F'0000) >> 2) | ((raw & 0x0000'7F00) >> 1) |
         ((raw & 0x0000'007F) >> 0);
}

inline std::size_t GetID3HeaderSize(uint32_t magic, const uint8_t* buf, std::size_t len) {
  if (len < 10) {
    return 0;
  }

  // ID3v1 and ID3v1.1: flat 128 bytes
  constexpr uint32_t kID3v1Masks = 0xFF'FF'FF'00u;  // Select first 3 bytes
  constexpr uint32_t kID3v1Value = 0x54'41'47'00u;  // 'TAG\x00'
  if ((magic & kID3v1Masks) == kID3v1Value) {
    return 128;
  }

  constexpr uint32_t kID3v2Masks = 0xFF'FF'FF'00u;  // Select first 3 bytes
  constexpr uint32_t kID3v2Value = 0x49'44'33'00u;  // 'ID3\x00'
  if ((magic & kID3v2Masks) != kID3v2Value) {
    return 0;
  }

  // file = 'ID3'
  //        uint8_t(ver_major) uint8_t(ver_minor)
  //        uint8_t(flags)
  //        uint32_t(inner_tag_size)
  //        byte[inner_tag_size] id3v2 data
  //        byte[*] original_file_content
  const auto id3v2InnerTagSize = ParseID3SyncSafeInt(&buf[6]);
  if (id3v2InnerTagSize == 0) {
    return 0;
  }

  return 10 + id3v2InnerTagSize;
}

inline std::size_t GetAPEv2FullSize(uint32_t magic1, const uint8_t* buf, std::size_t len) {
  uint32_t magic2 = parakeet_crypto::ReadBigEndian<uint32_t>(&buf[4]);
  constexpr uint32_t kAPEv2Magic1 = 0x41'50'45'54u;  // 'APET'
  constexpr uint32_t kAPEv2Magic2 = 0x41'47'45'58u;  // 'AGEX'

  if (magic1 != kAPEv2Magic1 || magic2 != kAPEv2Magic2) {
    return 0;
  }

  // Tag size in bytes including footer and all tag items excluding the header.
  constexpr std::size_t kAPEv2HeaderSize = 32;
  return parakeet_crypto::ReadLittleEndian<uint32_t>(&buf[0x0c]) + kAPEv2HeaderSize;
}

/**
 * @brief Detect ID3v2/APEv2 Tag size.
 *        When detected, a positive integer indicating its size from `buf`
 *        will be returned.
 *
 * @param buf
 * @param len
 * @return std::size_t
 */
inline std::size_t GetAudioHeaderMetadataSize(const uint8_t* buf, std::size_t len) {
  // Not enough bytes to detect
  if (len < 10) {
    return 0;
  }

  uint32_t magic = parakeet_crypto::ReadBigEndian<uint32_t>(buf);
  std::size_t id3_meta_size = GetID3HeaderSize(magic, buf, len);
  if (id3_meta_size) {
    return id3_meta_size;
  }

  // It's possible to have APEv2 header at the beginning of a file, though rare.
  std::size_t ape_meta_size = GetAPEv2FullSize(magic, buf, len);
  if (ape_meta_size) {
    return ape_meta_size;
  }

  return 0;
}

}  // namespace parakeet_crypto::utils
