#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <vector>

#include "parakeet-crypto/decryptor/qmc/QMCLoader.h"
#include "test/helper.test.hh"

using namespace parakeet_crypto::decryptor::tencent;
using namespace parakeet_crypto::decryptor;
using namespace parakeet_crypto;

TEST(QMCv1, StaticCipher) {
    std::vector<uint8_t> test_data(test::kSize4MiB);
    test::GenerateTestData(test_data, "qmcv1 static data");

    QMCv1Key key(256);
    test::GenerateTestData(key, "qmcv1 static key");

    auto result = test::DecryptTestContent(CreateQMCv1StaticDecryptor(key), test_data);

    test::VerifyHash(result, "2f9c936ed130a654911e0e2bc872fec33c90288e78df2a0aa41d352164c3b4e3");
}

TEST(QMCv1, MapCipher) {
    std::vector<uint8_t> test_data(test::kSize4MiB);
    test::GenerateTestData(test_data, "qmcv1 map cipher data");

    QMCv1Key key(256);
    test::GenerateTestData(key, "qmcv1 map cipher derived key");

    auto result = test::DecryptTestContent(CreateQMCv1MapDecryptor(key), test_data);

    test::VerifyHash(result, "ce84e9ac24ef5b2f02a11f74ffa8eb7008fe2898855617596c5ee217139fc214");
}
