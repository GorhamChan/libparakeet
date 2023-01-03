#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <vector>

#include "parakeet-crypto/decryptor/qmc2/QMCv2Loader.h"
#include "parakeet-crypto/misc/QMCFooterParser.h"
#include "parakeet-crypto/misc/QMCKeyDeriver.h"
#include "test/helper.test.hh"
#include "utils/EndianHelper.h"
#include "utils/base64.h"

using ::testing::ElementsAreArray;

using namespace parakeet_crypto::decryptor;
using namespace parakeet_crypto;
using namespace parakeet_crypto::misc::tencent;

TEST(QMCv2, RC4Cipher) {
    std::vector<uint8_t> test_data(test::kSize4MiB);
    test::GenerateTestData(test_data, "qmcv2 rc4 cipher data");

    std::vector<uint8_t> ekey;
    std::vector<uint8_t> file_key(512);
    std::vector<uint8_t> parsed_file_key;
    test::GenerateTestData(file_key, "qmcv2 rc4 cipher key");

    // chosen by fair dice roll.
    // guaranteed to be random.
    std::fill_n(file_key.begin(), 8, '4');

    auto result = test::DecryptTestContent(CreateQMCv2Decryptor(file_key), test_data);

    test::VerifyHash(result, "757fc9aa94ab48295b106a16452b7da7b90395be8e3132a077b6d2a9ea216838");
}
