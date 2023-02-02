#pragma once

#include <cassert>
#include <cstdint>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

namespace parakeet_crypto::test
{

inline std::optional<std::vector<uint8_t>> read_file(const char *path)
{
    std::ifstream ifs(path, std::ifstream::binary);
    if (!ifs.is_open())
    {
        return {};
    }
    ifs.seekg(0, std::ifstream::end);
    size_t file_len = ifs.tellg();
    std::vector<uint8_t> result(file_len);

    ifs.seekg(0, std::ifstream::beg);
    ifs.read(reinterpret_cast<char *>(result.data()), static_cast<std::streamsize>(file_len)); // NOLINT
    return result;
}

inline bool write_file(const char *path, const uint8_t *p_data, std::streamsize len)
{
    std::ofstream ofs(path, std::ofstream::binary);
    if (!ofs.is_open())
    {
        return false;
    }

    ofs.write(reinterpret_cast<const char *>(p_data), len); // NOLINT
    return !ofs.bad();
}

inline std::vector<uint8_t> read_fixture(const char *name)
{
    std::string file_path("fixture/");
    file_path += name;

    for (int i = 0; i < 2; i++)
    {
        if (auto data = read_file(file_path.c_str()); data.has_value())
        {
            return data.value();
        }

        file_path = std::string("../") + file_path; // NOLINT
    }

    assert(0); // Could not read fixture
    return {};
}

} // namespace parakeet_crypto::test
