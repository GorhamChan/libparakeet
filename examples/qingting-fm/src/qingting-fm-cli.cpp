#include "../../arg_parser.hpp"
#include "parakeet-crypto/qmc2/key_crypto.h"

#include <memory>
#include <parakeet-crypto/ITransformer.h>
#include <parakeet-crypto/StreamHelper.h>
#include <parakeet-crypto/transformer/qingting_fm.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <vector>

void print_help()
{
    std::cerr << std::endl;
    std::cerr << "usage: " << std::endl;
    std::cerr << "" << std::endl
              << "Secret key derivation from `android.os.Build` constants" << std::endl
              << "  --product              value of `android.os.Build.PRODUCT`" << std::endl
              << "  --device               value of `android.os.Build.DEVICE`" << std::endl
              << "  --manufacturer         value of `android.os.Build.MANUFACTURER`" << std::endl
              << "  --brand                value of `android.os.Build.BRAND`" << std::endl
              << "  --board                value of `android.os.Build.BOARD`" << std::endl
              << "  --model                value of `android.os.Build.MODEL`" << std::endl
              << "" << std::endl
              << "Secret key" << std::endl
              << "  -k | --secret-key <path>    Path to input file" << std::endl
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

    auto o_args = parse_args(argc, argv, {{"i", "input"}, {"o", "output"}, {"k", "secret-key"}}, print_help);
    if (!o_args)
    {
        return 1;
    }

    auto args = std::move(*o_args);
    auto path_file_in = args->get_string("input");
    auto path_file_out = args->get_string("output");

    // device id
    auto device_product = args->get_string("product");
    auto device_device = args->get_string("device");
    auto device_manufacturer = args->get_string("manufacturer");
    auto device_brand = args->get_string("brand");
    auto device_board = args->get_string("board");
    auto device_model = args->get_string("model");

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

    // secret key validation
    std::unique_ptr<ITransformer> transformer{};
    auto secret_key_hex = args->get_string("device-key");
    if (secret_key_hex)
    {
        std::vector<uint8_t> secret_key(secret_key_hex->begin(), secret_key_hex->end());
        secret_key.resize(16);
        transformer = transformer::CreateAndroidQingTingFMTransformer(path_file_in->c_str(), secret_key.data());
    }
    else if (device_product && device_device && device_manufacturer && device_brand && device_board && device_model)
    {
        transformer = transformer::CreateAndroidQingTingFMTransformer(
            path_file_in->c_str(), device_product->c_str(), device_device->c_str(), device_manufacturer->c_str(),
            device_brand->c_str(), device_board->c_str(), device_model->c_str());
    }
    else
    {
        print_help();
        std::cerr << "ERROR: missing parameters for secret key generation" << std::endl;
        return 2;
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
