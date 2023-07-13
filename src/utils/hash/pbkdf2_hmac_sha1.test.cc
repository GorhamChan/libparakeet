#include <cstdint>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "parakeet-crypto/utils/hash/md5.h"
#include "parakeet-crypto/utils/hash/pbkdf2_hmac_sha1.h"

#include <algorithm>
#include <array>
#include <sstream>
#include <string>
#include <vector>

using ::testing::ContainerEq;

using namespace parakeet_crypto::utils::hash;

// Test vector from rfc6070

// NOLINTBEGIN(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)

TEST(Utils_PKKDF2_HMAC_SHA1, rfc6070)
{
    struct test_case_data
    {
        std::string password;
        std::string salt;
        uint32_t iter_count;
        size_t derived_len;
        std::vector<uint8_t> expected;
    };

    std::vector<test_case_data> test_cases{
        {"password",
         "salt",
         1,
         20, //
         {0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9,
          0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06, 0x2f, 0xe0, 0x37, 0xa6}},

        {"password",
         "salt",
         2,
         20, //
         {0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c, 0xcd, 0x1e,
          0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0, 0xd8, 0xde, 0x89, 0x57}},

        {"password",
         "salt",
         4096,
         20, //
         {0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a, 0xbe, 0xad,
          0x49, 0xd9, 0x26, 0xf7, 0x21, 0xd0, 0x65, 0xa4, 0x29, 0xc1}},

        // This test case can take quite a few seconds in Release build.
        // Keep it here for reference only.
        // {"password",
        //  "salt",
        //  16777216,
        //  20, //
        //  {0xee, 0xfe, 0x3d, 0x61, 0xcd, 0x4d, 0xa4, 0xe4, 0xe9, 0x94,
        //   0x5b, 0x3d, 0x6b, 0xa2, 0x15, 0x8c, 0x26, 0x34, 0xe9, 0x84}},

        {"passwordPASSWORDpassword",
         "saltSALTsaltSALTsaltSALTsaltSALTsalt",
         4096,
         25, //
         {0x3d, 0x2e, 0xec, 0x4f, 0xe4, 0x1c, 0x84, 0x9b, 0x80, 0xc8, 0xd8, 0x36, 0x62,
          0xc0, 0xe4, 0x4a, 0x8b, 0x29, 0x1a, 0x96, 0x4c, 0xf2, 0xf0, 0x70, 0x38}},

        {std::string("pass\0word", 9),
         std::string("sa\0lt", 5),
         4096,
         16, //
         {0x56, 0xfa, 0x6a, 0xa7, 0x55, 0x48, 0x09, 0x9d, 0xcc, 0x37, 0xd7, 0xf0, 0x34, 0x25, 0xe0, 0xc3}},

    };

    for (auto &test_case : test_cases)
    {
        auto actual_key =
            pbkdf2_hmac_sha1(test_case.password, test_case.salt, test_case.iter_count, test_case.derived_len);

        std::stringstream test_name{};
        test_name << "test(password='" << test_case.password << "', salt='" << test_case.salt << "',";
        test_name << " iter_count=" << int(test_case.iter_count) << ", derived_len=" << test_case.derived_len << ")";

        ASSERT_THAT(actual_key, ContainerEq(test_case.expected)) << test_name.str();
    }
}

// NOLINTEND(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)
