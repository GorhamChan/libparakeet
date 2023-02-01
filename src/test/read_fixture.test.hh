#pragma once

#include <cassert>
#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

namespace parakeet_crypto::test
{

inline std::vector<uint8_t> read_fixture(const char *name)
{
    std::string file_path("fixture/");
    file_path += name;

    std::ifstream ifs_fixture(file_path.c_str(), std::ifstream::binary);
    if (!ifs_fixture.is_open())
    {
        file_path = std::string("../") + file_path;
        ifs_fixture.open(file_path.c_str(), std::ifstream::binary);
    }
    assert(ifs_fixture.is_open() == true);
    ifs_fixture.seekg(0, std::ifstream::end);
    size_t fixture_len = ifs_fixture.tellg();
    ifs_fixture.seekg(0, std::ifstream::beg);

    std::vector<uint8_t> result(fixture_len);
    ifs_fixture.read(reinterpret_cast<char *>(result.data()), static_cast<std::streamsize>(fixture_len)); // NOLINT
    return result;
}

} // namespace parakeet_crypto::test
