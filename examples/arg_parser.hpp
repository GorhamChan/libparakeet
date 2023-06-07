#pragma once

#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>

class ArgMapWrapper
{
  private:
    std::map<std::string, std::string> args_;

  public:
    ArgMapWrapper(std::map<std::string, std::string> args) : args_(std::move(args))
    {
    }

    inline std::string get_string(const std::string &key, std::string fallback)
    {
        if (auto value = get_string(key))
        {
            return *value;
        }

        return fallback;
    }

    inline std::optional<std::string> get_string(const std::string &key)
    {
        auto value = args_.find(key);
        if (value == args_.end())
        {
            return {};
        }
        return value->second;
    }

    inline int get_int(const std::string &key, int fallback)
    {
        if (auto value = get_int(key))
        {
            return *value;
        }

        return fallback;
    }

    inline std::optional<int> get_int(const std::string &key)
    {
        if (auto value = get_string(key))
        {
            return std::stoi(*value);
        }

        return {};
    }
};

inline std::optional<std::unique_ptr<ArgMapWrapper>> parse_args(int argc, char **argv,
                                                                std::map<std::string, std::string> short_to_long_map,
                                                                const std::function<void()> &print_help)
{
#if _WIN32
    setlocale(LC_ALL, ".65001");
#endif

    std::map<std::string, std::string> result;

    for (auto i = 1; i < argc; i++)
    {
        std::string arg_name{};
        if (argv[i][0] == '-' && argv[i][1] == '-')
        {
            arg_name = argv[i] + 2;
        }
        else if (argv[i][0] == '-')
        {
            auto it_long_item = short_to_long_map.find(std::string(&argv[i][1]));
            if (it_long_item != short_to_long_map.end())
            {
                arg_name = it_long_item->second;
            }
            else
            {
                std::cerr << "ERROR: unknown argument (" << argv[i] << ")" << std::endl;
                print_help();
                return {};
            }
        }
        else
        {
            std::cerr << "ERROR: unknown arguments" << std::endl;
            print_help();
            return {};
        }

        if (arg_name == "help")
        {
            print_help();
            return {};
        }

        result[arg_name] = argv[++i];
    }

    return std::make_unique<ArgMapWrapper>(result);
}
