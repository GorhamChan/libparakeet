#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <parakeet-crypto/version.h>

TEST(VersionTest, ItShouldPopulateVersion) {
  parakeet_crypto::get_libparakeet_version();
}
