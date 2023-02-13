#include "parakeet-crypto/ITransformer.h"
#include "parakeet-crypto/transformer/xiami.h"
#include "utils/endian_helper.h"
#include "utils/paged_reader.h"

#include <algorithm>
#include <array>
#include <cstdint>

namespace parakeet_crypto::transformer
{

// Xiami file header
// offset  description
//   0x00  "ifmt"
//   0x04  Format name, e.g. "FLAC".
//   0x08  0xfe, 0xfe, 0xfe, 0xfe
//   0x0C  (3 bytes) Little-endian, size of data to copy without modification.
//         e.g. [ 8a 19 00 ] = 6538 bytes of plaintext data.
//   0x0F  (1 byte) File key, applied to
//   0x10  Plaintext data
//   ????  Encrypted data

class XiamiDecryptionTransformer final : public ITransformer
{
  public:
    XiamiDecryptionTransformer() = default;

    const char *GetName() override
    {
        return "Xiami";
    }

    TransformResult Transform(IWriteable *output, IReadSeekable *input) override
    {
        constexpr std::array<uint8_t, 4> kMagicHeader1 = {'i', 'f', 'm', 't'};
        constexpr size_t kMagicHeader1Offset = 0x00;
        constexpr std::array<uint8_t, 4> kMagicHeader2 = {0xfe, 0xfe, 0xfe, 0xfe};
        constexpr size_t kMagicHeader2Offset = 0x08;

        constexpr size_t kHeaderSize = 0x10;
        constexpr size_t kHeaderKeyOffset = 0x0C;
        constexpr size_t kLittleEndianOffsetMask = 0x00FFFFFF;

        std::array<uint8_t, kHeaderSize> header{};
        if (!input->ReadExact(header.data(), header.size()))
        {
            return TransformResult::ERROR_INSUFFICIENT_INPUT;
        }
        if (!std::equal(kMagicHeader1.begin(), kMagicHeader1.end(), &header.at(kMagicHeader1Offset)) ||
            !std::equal(kMagicHeader2.begin(), kMagicHeader2.end(), &header.at(kMagicHeader2Offset)))
        {
            return TransformResult::ERROR_INVALID_FORMAT;
        }
        size_t copy_len = ReadLittleEndian<uint32_t>(&header.at(kHeaderKeyOffset)) & kLittleEndianOffsetMask;

        auto copy_ok = utils::PagedReader{input}.ReadInPages(copy_len, [&](size_t /*offset*/, uint8_t *buff, size_t n) {
            return output->Write(buff, n); //
        });

        if (!copy_ok)
        {
            return TransformResult::ERROR_OTHER;
        }

        uint8_t key = header.back() - uint8_t{1};
        auto decrypt_ok = utils::PagedReader{input}.ReadInPages([&](size_t /*offset*/, uint8_t *buffer, size_t n) {
            std::transform(buffer, buffer + n, buffer, [&](auto value) {
                return static_cast<uint8_t>(key - value); //
            });
            return output->Write(buffer, n);
        });

        return decrypt_ok ? TransformResult::OK : TransformResult::ERROR_OTHER;
    }
};

std::unique_ptr<ITransformer> CreateXiamiDecryptionTransformer()
{
    return std::make_unique<XiamiDecryptionTransformer>();
}

} // namespace parakeet_crypto::transformer
