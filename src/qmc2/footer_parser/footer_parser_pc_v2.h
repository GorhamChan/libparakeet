#pragma once

#include "parakeet-crypto/qmc2/footer_parser.h"
#include "parakeet-crypto/qmc2/key_crypto.h"
#include "utils/endian_helper.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <memory>
#include <utility>

namespace parakeet_crypto::qmc2
{

// QQ Music Ex tag.
// NOLINTBEGIN (*-c-arrays)
#pragma pack(push, 1)
struct QQMusicTagMusicExTail
{
    uint32_t sizeof_struct; // 19.57: fixed value: 0xC0
    uint32_t version;       // 19.57: fixed value: 0x01
    char tag_magic[8];      // fixed value "musicex\0"
};

struct QQMusicTagMusicEx
{
    uint32_t unknown_0;     // unused & unknown
    uint32_t unknown_1;     // unused & unknown
    uint32_t unknown_2;     // unused & unknown
    uint16_t mid[30];       // Media ID
    uint16_t mediafile[50]; // real file name
    uint32_t unknown_3;     // unused; uninitialized memory?

    QQMusicTagMusicExTail tail; // actual tail
};
#pragma pack(pop)

constexpr std::array<uint8_t, 8> kMusicExTailMagic = {'m', 'u', 's', 'i', 'c', 'e', 'x', 0};

// NOLINTEND (*-c-arrays)

class FooterParserPCMusicEx
{
  public:
    FooterParserPCMusicEx() = default;

    static inline bool IsPCMusicExFooter(const QQMusicTagMusicExTail *tail)
    {
        if (!std::equal(kMusicExTailMagic.cbegin(), kMusicExTailMagic.cend(), &tail->tag_magic[0]))
        {
            return false; // magic mismatch
        }

        if (tail->version != 1)
        {
            return false; // version mismatch
        }

        return true;
    }

    static inline std::unique_ptr<FooterParseResult> Parse(const uint8_t *file_footer, size_t len)
    {
        const auto *tail_music_magic =
            // NOLINTNEXTLINE(*-reinterpret-cast)
            reinterpret_cast<const QQMusicTagMusicExTail *>(&file_footer[len - sizeof(QQMusicTagMusicExTail)]);

        // Check for overflow size
        if (tail_music_magic->sizeof_struct > sizeof(QQMusicTagMusicEx))
        {
            return std::make_unique<FooterParseResult>(FooterParseState::MusicExBufferOverflow);
        }

        // Check for size required
        if (len < tail_music_magic->sizeof_struct)
        {
            return std::make_unique<FooterParseResult>(FooterParseState::NeedMoreBytes,
                                                       tail_music_magic->sizeof_struct);
        }

        // Fetch the whole musicex tag
        QQMusicTagMusicEx tag{};
        memcpy(&tag, &file_footer[len - tail_music_magic->sizeof_struct], tail_music_magic->sizeof_struct);

        // Since media_file_name only uses ascii chars, we can convert them without issues.
        constexpr size_t kMediaFileLen = sizeof(tag.mediafile) / sizeof(tag.mediafile[0]) - 1;

        // make a copy of the name
        std::string media_file_name{};
        media_file_name.reserve(kMediaFileLen);
        for (size_t i = 0; i < kMediaFileLen && tag.mediafile[i] != 0; i++)
        {
            media_file_name.push_back(static_cast<char>(tag.mediafile[i]));
        }

        return std::make_unique<FooterParseResult>(FooterParseState::OK, tail_music_magic->sizeof_struct,
                                                   media_file_name);
    }
};

} // namespace parakeet_crypto::qmc2
