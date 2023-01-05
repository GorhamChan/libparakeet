#include "parakeet-crypto/decryptor/qmc/QMCTailParser.h"

#include "utils/EndianHelper.h"
#include "utils/StringHelper.h"

#include <algorithm>
#include <array>
#include <utility>

namespace parakeet_crypto::qmc {

namespace detail {

using parakeet_crypto::utils::ParseCSVLine;

class TailParserImpl : public TailParser {
   public:
    TailParserImpl(std::shared_ptr<KeyCrypto> key_crypto) : key_crypto_(std::move(key_crypto)){};
    ~TailParserImpl() override = default;

    std::optional<std::pair<std::size_t, std::vector<uint8_t>>> Parse(std::span<const uint8_t> data) const override {
        constexpr std::size_t kCommonEndingSize = 4;

        if (data.size() < kCommonEndingSize) {
            return {};
        }

        std::array<uint8_t, kCommonEndingSize> ending{};
        std::copy_n(data.end() - kCommonEndingSize, kCommonEndingSize, ending.begin());

        const static auto kMagicSTag = std::to_array<uint8_t>({'S', 'T', 'a', 'g'});
        const static auto kMagicQTag = std::to_array<uint8_t>({'Q', 'T', 'a', 'g'});

        // STag: Android Client Encrypted format since 2022.04, does not contain an embedded key.
        if (std::equal(kMagicSTag.cbegin(), kMagicSTag.cend(), ending.cbegin())) {
            return {};
        }

        std::optional<std::pair<std::size_t, std::string>> parse_result;

        if (std::equal(kMagicQTag.cbegin(), kMagicQTag.cend(), ending.cbegin())) {
            // Legacy android format, with embedded metadata & keys.
            parse_result = ParseAndroidClientTail(data);
        } else {
            // Windows client, end with meta size.
            parse_result = ParsePCClientTail(data);
        }

        if (!parse_result) {
            return {};
        }

        // We got a valid tail, now let's attempt to decrypt its key...
        if (auto key = key_crypto_->Decrypt(parse_result->second)) {
            return std::make_pair(parse_result->first, *key);
        }

        return {};
    }

    static inline std::optional<std::pair<std::size_t, std::string>> ParseAndroidClientTail(
        std::span<const uint8_t> data) {
        // Legacy Android format.
        //   metadata := [ansi ekey_b64] ","
        //               [ansi song_id] ","
        //               [ansi metadata_version '2']
        //   eof_mark := [(be)uint32_t meta_len] [bytes 'QTag']
        //   qmc_file := [encrypted_data] [metadata] [eof_mark]
        //
        // Where:
        //   meta_len := bytes( [metadata] [eof_mark] ).size()
        constexpr std::size_t kOffsetFromMetaSize = 8;

        if (data.size() < kOffsetFromMetaSize) {
            return {};
        }

        auto meta_len = ReadBigEndian<uint32_t>(&data[data.size() - kOffsetFromMetaSize]);

        size_t tail_size = meta_len + kOffsetFromMetaSize;
        if (data.size() < tail_size) {
            return {};
        }

        auto metadata = ParseCSVLine(std::span{data.end() - tail_size, meta_len});

        // We should see the following:
        //    ekey_b64, song id and metadata version;
        // where metadata version should be '2'.
        if (metadata.size() != 3 || metadata[2] != "2") {
            return {};
        }

        return std::make_pair(tail_size, metadata[0]);
    }

    static inline std::optional<std::pair<std::size_t, std::string>> ParsePCClientTail(std::span<const uint8_t> data) {
        // Legacy PC QQMusic encoded format.
        // ekey_b64 := [ansi ekey_b64]
        // eof_mark := [(le)uint32_t ekey_size]
        // qmc_file := [encrypted_data] [ekey_b64] [eof_mark]
        if (data.size() < 4) {
            return {};
        }

        auto ekey_size = ReadLittleEndian<uint32_t>(&data[data.size() - 4]);

        size_t tail_size = ekey_size + 4;
        if (data.size() < tail_size) {
            return {};
        }

        return std::make_pair(tail_size, std::string(data.end() - tail_size, data.end() - 4));
    }

   private:
    std::shared_ptr<KeyCrypto> key_crypto_;
};

}  // namespace detail

std::unique_ptr<TailParser> CreateTailParser(const std::shared_ptr<KeyCrypto>& key_crypto) {
    return std::make_unique<detail::TailParserImpl>(key_crypto);
}

}  // namespace parakeet_crypto::qmc
