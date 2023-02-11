
#include <gtest/gtest.h>

namespace parakeet_crypto::test::setup
{

class WindowsUTF8Environment : public ::testing::Environment
{
  public:
    ~WindowsUTF8Environment() override = default;

    void SetUp() override
    {
#if _WIN32
        setlocale(LC_ALL, ".65001");
#endif
    }

    void TearDown() override
    {
    }
};

const auto win32_utf8 = testing::AddGlobalTestEnvironment(new WindowsUTF8Environment()); // NOLINT

}; // namespace parakeet_crypto::test::setup
