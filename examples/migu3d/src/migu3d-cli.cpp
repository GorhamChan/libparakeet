#include "parakeet-crypto/ITransformer.h"
#include <parakeet-crypto/StreamHelper.h>

#include <parakeet-crypto/transformer/migu3d.h>

#include <array>
#include <cstring>
#include <fstream>
#include <iostream>
#include <vector>

void print_help()
{
    std::cerr << std::endl;
    std::cerr << "usage: " << std::endl;
    std::cerr << "  --salt <salt>          Application salt" << std::endl
              << "  --file-key <key>       File specific key " << std::endl
              << "  -i | --input <path>    Path to input file" << std::endl
              << "  -o | --output <path>   Path to output file" << std::endl
              << "  -h | --help            Display this usage information" << std::endl;
    std::cerr << std::endl;
    std::cerr << "When --salt and --file-key are both omitted, "
                 "it will attempt to recover the key by performing frequency analysis attack."
              << std::endl;
    std::cerr << std::endl;
}

// NOLINTBEGIN(*-magic-numbers)
int main(int argc, char **argv)
{
    using namespace parakeet_crypto;

#if _WIN32
    setlocale(LC_ALL, ".65001");
#endif

    std::string salt{};
    std::string file_key{};
    std::string path_file_input{};
    std::string path_file_output{};

    for (auto i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--salt") == 0)
        {
            salt = argv[++i];
        }
        else if (strcmp(argv[i], "--file-key") == 0)
        {
            file_key = argv[++i];
        }
        else if (strcmp(argv[i], "--input") == 0 || strcmp(argv[i], "-i") == 0)
        {
            path_file_input = argv[++i];
        }
        else if (strcmp(argv[i], "--output") == 0 || strcmp(argv[i], "-o") == 0)
        {
            path_file_output = argv[++i];
        }
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0)
        {
            print_help();
            return 0;
        }
        else if (path_file_input.empty())
        {
            path_file_input = argv[i];
        }
        else if (path_file_output.empty())
        {
            path_file_output = argv[i];
        }
        else
        {
            print_help();
            return 1;
        }
    }

    if (path_file_input.empty() || path_file_output.empty())
    {
        print_help();
        return 1;
    }

    std::ifstream input_file(path_file_input, std::ifstream::binary);
    if (!input_file.is_open())
    {
        std::cerr << "ERROR: could not open input file" << std::endl;
        return 1;
    }

    std::ofstream output_file(path_file_output, std::ofstream::binary);
    if (!output_file.is_open())
    {
        std::cerr << "ERROR: could not open output file" << std::endl;
        return 1;
    }

    // Create our transformer

    std::vector<uint8_t> param_salt(salt.begin(), salt.end());
    std::vector<uint8_t> param_file_key(file_key.begin(), file_key.end());
    param_salt.resize(32);
    param_file_key.resize(32);

    auto transformer = (salt.empty() || file_key.empty())
                           ? transformer::CreateKeylessMiguTransformer()
                           : transformer::CreateMiguTransformer(param_salt.data(), param_file_key.data());

    InputFileStream reader{input_file};
    OutputFileStream writer{output_file};

    // Perform decryption...
    auto decryption_result = transformer->Transform(&writer, &reader);
    if (decryption_result != TransformResult::OK)
    {
        std::cerr << "decryption failed - error(" << static_cast<uint32_t>(decryption_result) << ")" << std::endl;
        return 1;
    }

    std::cout << "done!" << std::endl;
    return 0;
}

// NOLINTEND(*-magic-numbers)
