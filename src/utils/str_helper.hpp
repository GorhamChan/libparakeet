#pragma once

#include <string>
#include <string_view>

namespace parakeet_crypto::utils::str
{

inline bool endsWith(std::string_view str, std::string_view suffix)
{
    return str.size() >= suffix.size() && 0 == str.compare(str.size() - suffix.size(), suffix.size(), suffix);
}

inline bool startsWith(std::string_view str, std::string_view prefix)
{
    return str.size() >= prefix.size() && 0 == str.compare(0, prefix.size(), prefix);
}

inline std::string getFirstItemBeforeToken(std::string_view str, char token)
{
    if (auto pos = str.find(token); pos != std::string::npos)
    {
        return std::string(str.substr(0, pos));
    }

    return std::string(str);
}

inline std::string getLastItemAfterToken(std::string_view str, char token)
{
    if (auto pos = str.rfind(token); pos != std::string::npos)
    {
        return std::string(str.substr(pos + 1));
    }

    return std::string(str);
}

inline std::string stripPrefix(std::string_view str, std::string_view prefix)
{
    if (startsWith(str, prefix))
    {
        return std::string(str.substr(prefix.size()));
    }

    return std::string(str);
}

inline std::string stripSuffix(std::string_view str, std::string_view suffix)
{
    if (endsWith(str, suffix))
    {
        return std::string(str.substr(0, str.size() - suffix.size()));
    }

    return std::string(str);
}

} // namespace parakeet_crypto::utils::str
