#pragma once

#include "test/test_env.h"

#include <cassert>
#include <cstdint>
#include <fstream>
#include <ios>
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
    std::vector<uint8_t> result(file_len, 0);

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

inline bool write_local_file(const char *name, const std::vector<uint8_t> &data)
{
    std::string file_path(get_local_file_directory());
    file_path += name;

    return write_file(file_path.c_str(), data.data(), static_cast<std::streamsize>(data.size()));
}

inline std::vector<uint8_t> read_fixture(const char *name)
{
    std::string file_path(get_fixture_directory());
    file_path += name;

    if (auto data = read_file(file_path.c_str()); data.has_value())
    {
        return *data;
    }

    return {};
}

inline std::vector<uint8_t> read_local_file(const char *name)
{
    std::string file_path(get_local_file_directory());
    file_path += name;

    if (auto data = read_file(file_path.c_str()); data.has_value())
    {
        return *data;
    }

    return {};
}

} // namespace parakeet_crypto::test
