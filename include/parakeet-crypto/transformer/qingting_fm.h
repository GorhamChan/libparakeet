#pragma once

#include "parakeet-crypto/ITransformer.h"

#include <memory>
#include <string>

namespace parakeet_crypto::transformer
{

/**
 * Create QingTingFM transformer with file name and device properties.
 *
 * @param filename file name
 * @param product         `Build.PRODUCT`
 * @param device          `Build.DEVICE`
 * @param manufacturer    `Build.MANUFACTURER`
 * @param brand           `Build.BRAND`
 * @param board           `Build.BOARD`
 * @param model           `Build.MODEL`
 * @example
 * To get the device information, run the following:
 *
 *     import android.os.Build;
 *
 *     var DeviceInfo = { Build.PRODUCT
 *                      , Build.DEVICE
 *                      , Build.MANUFACTURER
 *                      , Build.BRAND
 *                      , Build.BOARD
 *                      , Build.MODEL         };
 */
std::unique_ptr<ITransformer> CreateAndroidQingTingFMTransformer( //
    const char *filename, const char *product, const char *device, const char *manufacturer, const char *brand,
    const char *board, const char *model);

/**
 * Create QingTingFM transformer with file name and pre-computed device fingerprint.
 *
 * @param filename file name
 * @param device_fingerprint pre-computed device fingerprint, 16 bytes.
 */
std::unique_ptr<ITransformer> CreateAndroidQingTingFMTransformer(const char *filename,
                                                                 const uint8_t *device_fingerprint);

} // namespace parakeet_crypto::transformer
