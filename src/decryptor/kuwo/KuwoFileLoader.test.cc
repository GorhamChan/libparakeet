#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <vector>

#include "parakeet-crypto/decryptor/kuwo/KuwoFileLoader.h"
#include "test/helper.test.hh"

using ::testing::ElementsAreArray;

using namespace parakeet_crypto::decryptor;
using namespace parakeet_crypto;

const KuwoKey kKuwoKey = []() {
    KuwoKey result;
    test::GenerateTestData(result, "kuwo-test-key");
    return result;
}();

TEST(KuwoFileLoader, SimpleCase) {
    std::vector<uint8_t> test_data(test::kSize4MiB);

    test::GenerateTestData(test_data, "kuwo-data-1");

    auto header_override = std::to_array<uint8_t>({
        0x79, 0x65, 0x65, 0x6c, 0x69, 0x6f, 0x6e, 0x2d, 0x6b, 0x75, 0x77, 0x6f, 0x2d, 0x74, 0x6d, 0x65,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xEE, 0xDD, 0x11, 0x22, 0x33, 0x00, 0x00,
    });
    std::ranges::copy(header_override.cbegin(), header_override.cend(), test_data.begin());

    auto result = test::DecryptTestContent(CreateKuwoDecryptor(kKuwoKey), test_data);

    test::VerifyHash(result, "aefad6b6f75ecb915fd0211f02eeacbd9c28e51b22c06c6d1bb3c61c963feaae");
}
