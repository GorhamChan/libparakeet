#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <parakeet-crypto/version.h>
#include <iostream>

TEST(VersionTest, ItShouldPopulateVersion) {
  auto lib_version = parakeet_crypto::get_libparakeet_version();
  auto lib_full_version = parakeet_crypto::get_libparakeet_full_version();

  std::cerr << "lib_version: " << lib_version << std::endl;
  std::cerr << "lib_full_version: " << lib_full_version << std::endl;
}
