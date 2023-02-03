#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <iostream>
#include <parakeet-crypto/version.h>

// NOLINTBEGIN(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)

TEST(VersionTest, ItShouldPopulateVersion)
{
    const auto *lib_version = parakeet_crypto::get_libparakeet_version();
    const auto *lib_full_version = parakeet_crypto::get_libparakeet_full_version();

    std::cerr << "lib_version: " << lib_version << std::endl;
    std::cerr << "lib_full_version: " << lib_full_version << std::endl;
}

// NOLINTEND(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)
