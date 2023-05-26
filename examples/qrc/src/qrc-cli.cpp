#include "parakeet-crypto/ITransformer.h"
#include <parakeet-crypto/StreamHelper.h>

#include <parakeet-crypto/transformer/qmc.h>
#include <parakeet-crypto/transformer/qrc.h>

#include <array>
#include <fstream>
#include <iostream>
#include <vector>

// NOLINTBEGIN(*-magic-numbers)

// --- QRC Decryption Config
#if __has_include("qrc-key.local.h")
#include "qrc-key.local.h"
#else

// NOLINTBEGIN(*-avoid-c-arrays)

constexpr std::array<uint8_t, 128> qmc1StaticKey{};

constexpr uint8_t des_key1[] = "12345678";
constexpr uint8_t des_key2[] = "23456789";
constexpr uint8_t des_key3[] = "34567890";
// NOLINTEND(*-avoid-c-arrays)

#endif
// --- QRC Decryption Config

int main(int argc, char **argv)
{
    using namespace parakeet_crypto;

#if _WIN32
    setlocale(LC_ALL, ".65001");
#endif

    if (argc <= 2)
    {
        std::cerr << "ERROR: missing arguments" << std::endl;
        std::cerr << std::endl;
        std::cerr << "usage: " << std::endl;
        std::cerr << "  '" << argv[0] << "' <input> <output>" << std::endl;
        std::cerr << std::endl;
        return 1;
    }

    std::ifstream input_file(argv[1], std::ifstream::binary);
    if (!input_file.is_open())
    {
        std::cerr << "ERROR: could not open input file" << std::endl;
        return 1;
    }

    std::ofstream output_file(argv[2], std::ofstream::binary);
    if (!output_file.is_open())
    {
        std::cerr << "ERROR: could not open output file" << std::endl;
        return 1;
    }

    // Create our transformer
    // setup crypto
    std::shared_ptr<ITransformer> qmc_transformer = transformer::CreateQMC1StaticDecryptionTransformer(qmc1StaticKey);
    auto transformer =
        transformer::CreateQRCLyricsDecryptionTransformer(qmc_transformer, &des_key1[0], &des_key2[0], &des_key3[0]);

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
