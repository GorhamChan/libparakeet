/**
 * @file qrc.cpp
 * @brief [QQMusic] QRC Encrypted lyrics decryptor
 *
 * QRC File format:
 *
 * Magic header:
 *   0000h  98 25 B0 AC E3 02 83 68 E8 FC 6C          ˜%°¬ã.ƒhèül
 *
 * Decrypt this stream with QMC1 (same key).
 *
 * When decrypted, the magic header became:
 *
 *   0000h  5B 6F 66 66 73 65 74 3A 30 5D 0A          [offset:0].
 *
 * ... where the first 11 bytes will then be discarded.
 *
 * The rest of the data will be going through a modified 3-des (ECB Mode):
 *
 *   qrc_des::decrypt(&buffer, key1)
 *   qrc_des::encrypt(&buffer, key2)
 *   qrc_des::decrypt(&buffer, key3)
 *
 * Finally, call zlib's inflate.
 */

#include "parakeet-crypto/transformer/qrc.h"
#include "parakeet-crypto/IStream.h"
#include "parakeet-crypto/ITransformer.h"
#include "qrc_des.h"
#include "utils/buffered_transform.h"
#include "utils/endian_helper.h"
#include <algorithm>
#include <cstdint>
#include <memory>
#include <utility>

#include <zlib.h>

namespace parakeet_crypto::transformer
{

class RawDESTransformer final : public IWriteable
{
  private:
    static constexpr size_t kDESBlockSize = 8;
    const qrc::QRC_DES &des1_;
    const qrc::QRC_DES &des2_;
    const qrc::QRC_DES &des3_;
    IWriteable *dest_;

    BufferedTransform<kDESBlockSize> buffer_{};

  public:
    RawDESTransformer(IWriteable *dest, const qrc::QRC_DES &des1, const qrc::QRC_DES &des2, const qrc::QRC_DES &des3)
        : dest_(dest), des1_(des1), des2_(des2), des3_(des3)
    {
    }

    [[nodiscard]] bool Write(const uint8_t *buffer, size_t len) override
    {
        bool write_ok{true};
        std::array<uint8_t, kDESBlockSize> block{};
        buffer_.ProcessBuffer(buffer, len, [&](const uint8_t *buffer) {
            std::copy_n(buffer, block.size(), block.begin());
            des1_.decrypt_block(block.data());
            des2_.encrypt_block(block.data());
            des3_.decrypt_block(block.data());
            write_ok = dest_->Write(block.data(), block.size());
            return write_ok;
        });
        return write_ok;
    }
};

template <size_t DropTarget> class DropHeader final : public IWriteable
{
  private:
    IWriteable *dest_;
    size_t bytes_to_drop_{DropTarget};

  public:
    DropHeader(IWriteable *dest) : dest_(dest){};

    [[nodiscard]] bool Write(const uint8_t *buffer, size_t len) override
    {
        if (bytes_to_drop_ != 0)
        {
            size_t to_drop = std::min(bytes_to_drop_, len);
            buffer += to_drop;
            len -= to_drop;
            bytes_to_drop_ -= to_drop;
            if (bytes_to_drop_ != 0)
            {
                return true;
            }
        }

        return dest_->Write(buffer, len);
    }
};

class ZLibInflate final : public IWriteable
{
  private:
    IWriteable *dest_;
    std::array<uint8_t, 1024> buffer_{};
    z_stream strm_{};

  public:
    ZLibInflate(const ZLibInflate &) = default;
    ZLibInflate(ZLibInflate &&) = delete;
    ZLibInflate &operator=(const ZLibInflate &) = default;
    ZLibInflate &operator=(ZLibInflate &&) = delete;
    ZLibInflate(IWriteable *dest) : dest_(dest){};
    ~ZLibInflate() override
    {
        inflateEnd(&strm_);
    }

    [[nodiscard]] bool Write(const uint8_t *buffer, size_t len) override
    {
        return WriteInflator(buffer, len, Z_NO_FLUSH);
    }

    [[nodiscard]] bool WriteInflator(const uint8_t *buffer, size_t len, int flush)
    {
        if (strm_.next_in == nullptr)
        {
            if (inflateInit(&strm_) != Z_OK)
            {
                return false; // zlib init failed
            }
        }

        strm_.next_in = const_cast<uint8_t *>(buffer); // NOLINT(*-const-cast)
        strm_.avail_in = len;
        auto expected_in = strm_.total_in + len;

        int err{};

        do // NOLINT(*-avoid-do-while)
        {
            strm_.next_out = buffer_.data();
            strm_.avail_out = buffer_.size();
            err = inflate(&strm_, flush);
            if (!dest_->Write(buffer_.data(), buffer_.size() - strm_.avail_out))
            {
                return false;
            }
            if (err != Z_OK && err != Z_STREAM_END)
            {
                return false;
            }
        } while (strm_.avail_out == 0);

        return true;
    }

    bool Flush()
    {
        return WriteInflator(buffer_.data(), 0, Z_FINISH);
    }
};

class QRCTransformer final : public ITransformer
{
  private:
    std::shared_ptr<ITransformer> qmc1_static_transformer_;
    qrc::QRC_DES des1_;
    qrc::QRC_DES des2_;
    qrc::QRC_DES des3_;

  public:
    const char *GetName() override
    {
        return "QRC";
    }

    QRCTransformer(std::shared_ptr<ITransformer> qmc1_static_transformer, const uint8_t *key1, const uint8_t *key2,
                   const uint8_t *key3)
        : qmc1_static_transformer_(std::move(qmc1_static_transformer))
    {
        des1_.setup_key(key1);
        des2_.setup_key(key2);
        des3_.setup_key(key3);
    }

    TransformResult Transform(IWriteable *output, IReadSeekable *input) override
    {
        constexpr std::array<uint8_t, 11> kMagicEncryptedHeader = {
            0x98, 0x25, 0xB0, 0xAC, 0xE3, 0x02, 0x83, 0x68, 0xE8, 0xFC, 0x6C,
        };

        std::array<uint8_t, kMagicEncryptedHeader.size()> header{};
        if (!input->ReadExact(header.data(), header.size()))
        {
            return TransformResult::ERROR_INSUFFICIENT_INPUT;
        }

        if (!std::equal(kMagicEncryptedHeader.begin(), kMagicEncryptedHeader.end(), header.begin()))
        {
            return TransformResult::ERROR_INVALID_FORMAT;
        }

        input->Seek(0, SeekDirection::SEEK_FILE_BEGIN);

        ZLibInflate zlib(output);
        RawDESTransformer qrc_des(&zlib, des1_, des2_, des3_);
        DropHeader<kMagicEncryptedHeader.size()> header_removal(&qrc_des);

        auto result = qmc1_static_transformer_->Transform(&header_removal, input);
        if (result == TransformResult::OK)
        {
            if (!zlib.Flush())
            {
                return TransformResult::ERROR_IO_OUTPUT_UNKNOWN; // zlib inflate error?
            }
        }
        return result;
    }
};

std::unique_ptr<ITransformer> CreateQRCLyricsDecryptionTransformer(
    std::shared_ptr<ITransformer> qmc1_static_transformer, const uint8_t *key1, const uint8_t *key2,
    const uint8_t *key3)
{
    return std::make_unique<QRCTransformer>(std::move(qmc1_static_transformer), key1, key2, key3);
}

} // namespace parakeet_crypto::transformer
