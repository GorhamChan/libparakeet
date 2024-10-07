#include "parakeet-crypto/cipher/cipher_error.h"
#include "parakeet-crypto/transformer/qingting_fm.h"
#include "qingting_fm.h"

#include "parakeet-crypto/cipher/aes/aes.h"
#include "parakeet-crypto/cipher/block_mode/ctr.h"

#include "utils/paged_reader.h"

#include <memory>
#include <optional>
#include <string_view>

namespace parakeet_crypto::transformer
{

using namespace parakeet_crypto::qtfm;
using AES128CTR = cipher::block_mode::CTR_Stream<cipher::aes::AES128Enc>;

namespace qtfm_impl_details
{

class QingTingFMTransformer final : public ITransformer
{
  public:
    QingTingFMTransformer(const char *filename, const char *product, const char *device, const char *manufacturer,
                          const char *brand, const char *board, const char *model)
    {
        // NOLINTNEXTLINE(*-identifier-length)
        auto iv = CreateCryptoIV(filename, 0);
        auto secret_key = CreateDeviceSecretKey(product, device, manufacturer, brand, board, model);
        ctr_ = AES128CTR(std::make_shared<cipher::aes::AES128Enc>(secret_key), iv);
    };
    QingTingFMTransformer(const char *filename, const uint8_t *secret_key)
    {
        // NOLINTNEXTLINE(*-identifier-length)
        auto iv = CreateCryptoIV(filename, 0);
        ctr_ = AES128CTR(std::make_shared<cipher::aes::AES128Enc>(secret_key), iv);
    };

    const char *GetName() override
    {
        return "QingTingFM (qingting.fm)";
    }

    TransformResult Transform(IWriteable *output, IReadSeekable *input) override
    {
        auto success = utils::PagedReader{input}.ReadInPages([&](size_t /*offset*/, uint8_t *buffer, size_t n) {
            size_t buffer_size = n;
            if (auto err = ctr_->Update(buffer, buffer_size, buffer, n); err != cipher::CipherError::kSuccess)
            {
                return false;
            }

            return output->Write(buffer, n);
        });
        return success ? TransformResult::OK : TransformResult::ERROR_OTHER;
    }

  private:
    std::optional<AES128CTR> ctr_;
};
}; // namespace qtfm_impl_details

std::unique_ptr<ITransformer> CreateAndroidQingTingFMTransformer( //
    const char *filename, const char *product, const char *device, const char *manufacturer, const char *brand,
    const char *board, const char *model)
{
    return std::make_unique<qtfm_impl_details::QingTingFMTransformer>(filename, product, device, manufacturer, brand,
                                                                      board, model);
}

std::unique_ptr<ITransformer> CreateAndroidQingTingFMTransformer(const char *filename,
                                                                 const uint8_t *device_fingerprint)
{
    return std::make_unique<qtfm_impl_details::QingTingFMTransformer>(filename, device_fingerprint);
}

} // namespace parakeet_crypto::transformer
