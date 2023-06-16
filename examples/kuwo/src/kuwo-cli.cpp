#include "../../arg_parser.hpp"
#include "parakeet-crypto/qmc2/key_crypto.h"

#include <parakeet-crypto/ITransformer.h>
#include <parakeet-crypto/StreamHelper.h>
#include <parakeet-crypto/transformer/kuwo.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <vector>

// --- KWMv2(QMC2) Decryption Config
#if __has_include("../../qmc2/src/qmc2-key.local.h")
#include "../../qmc2/src/qmc2-key.local.h"
#else
static constexpr uint8_t qmc2_seed = 123;
static constexpr std::array<uint8_t, 16> qmc2_encv2_key1 = {
    11, 12, 13, 14, 15, 16, 17, 18, 21, 22, 23, 24, 25, 26, 27, 28,
};
static constexpr std::array<uint8_t, 16> qmc2_encv2_key2 = {
    31, 32, 33, 34, 35, 36, 37, 38, 41, 42, 43, 44, 45, 46, 47, 48,
};
#endif

void print_help()
{
    std::cerr << std::endl;
    std::cerr << "usage: " << std::endl;
    std::cerr << "" << std::endl
              << "KwmV1 decryption config" << std::endl
              << "  --key <key>            static key used for v1 encryption" << std::endl
              << "" << std::endl
              << "KwmV2 decryption config" << std::endl
              << "  --seed <seed>          ekey seed" << std::endl
              << "  --mix-key-1 <key>      [EncV2] mix key 1" << std::endl
              << "  --mix-key-2 <key>      [EncV2] mix key 2" << std::endl
              << "  --ekey [ekey]          EKey of the file (encrypted)" << std::endl
              << "" << std::endl
              << "IO parameters" << std::endl
              << "  -i | --input <path>    Path to input file" << std::endl
              << "  -o | --output <path>   Path to output file" << std::endl
              << "  -h | --help            Display this usage information" << std::endl;
    std::cerr << std::endl;
}

// NOLINTBEGIN(*-magic-numbers)
int main(int argc, char **argv)
{
    using namespace parakeet_crypto;

#if _WIN32
    setlocale(LC_ALL, ".65001");
#endif

    auto o_args = parse_args(argc, argv, {{"i", "input"}, {"o", "output"}}, print_help);
    if (!o_args)
    {
        return 1;
    }

    auto args = std::move(*o_args);
    auto path_file_in = args->get_string("input");
    auto path_file_out = args->get_string("output");
    auto key_str = args->get_string("key");
    auto ekey_str = args->get_string("ekey");

    if (!path_file_in)
    {
        std::cerr << "ERROR: input not specified" << std::endl;
        print_help();
        return 2;
    }

    if (!path_file_out)
    {
        std::cerr << "ERROR: output not specified" << std::endl;
        print_help();
        return 2;
    }

    std::array<uint8_t, 0x20> key{};
    if (key_str)
    {
        std::copy_n(key.begin(), std::min(key_str->size(), key.size()), key_str->begin());
    }

    auto seed = args->get_int("seed", qmc2_seed);

    std::array<uint8_t, 16> qmc2_encv2_key1_local{qmc2_encv2_key1};
    if (auto mix_key_1_str = args->get_string("mix-key-1"))
    {
        std::copy_n(mix_key_1_str->begin(), std::min(mix_key_1_str->size(), qmc2_encv2_key1_local.size()),
                    qmc2_encv2_key1_local.begin());
    }

    std::array<uint8_t, 16> qmc2_encv2_key2_local{qmc2_encv2_key2};
    if (auto mix_key_2_str = args->get_string("mix-key-2"))
    {
        std::copy_n(mix_key_2_str->begin(), std::min(mix_key_2_str->size(), qmc2_encv2_key2_local.size()),
                    qmc2_encv2_key2_local.begin());
    }

    auto key_crypto = qmc2::CreateKeyCrypto(seed, qmc2_encv2_key1_local.data(), qmc2_encv2_key2_local.data());

    std::vector<uint8_t> ekey;
    size_t footer_len_exclude{0};
    if (ekey_str)
    {
        footer_len_exclude = 0;
        ekey = key_crypto->Decrypt(reinterpret_cast<const uint8_t *>(ekey_str->c_str()), // NOLINT(*reinterpret-cast)
                                   ekey_str->size());
    }

    std::ifstream input_file(*path_file_in, std::ifstream::binary);
    if (!input_file.is_open())
    {
        std::cerr << "ERROR: could not open input file" << std::endl;
        return 1;
    }

    std::ofstream output_file(*path_file_out, std::ofstream::binary);
    if (!output_file.is_open())
    {
        std::cerr << "ERROR: could not open output file" << std::endl;
        return 1;
    }

    // Create our transformer
    auto transformer = transformer::CreateKuwoDecryptionTransformer(key.data(), std::move(ekey));

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
