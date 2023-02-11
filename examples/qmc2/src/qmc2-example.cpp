#include <parakeet-crypto/StreamHelper.h>

#include <parakeet-crypto/qmc2/footer_parser.h>
#include <parakeet-crypto/qmc2/key_crypto.h>
#include <parakeet-crypto/transformer/qmc.h>

#include <fstream>
#include <iostream>
#include <vector>

// NOLINTBEGIN(*-magic-numbers)

// --- QMC2 Decryption Config
#if __has_include("qmc2-key.local.h")
#include "qmc2-key.local.h"
#else
static constexpr uint8_t qmc2_seed = 123;
static constexpr std::array<uint8_t, 16> qmc2_encv2_key1 = {
    11, 12, 13, 14, 15, 16, 17, 18, 21, 22, 23, 24, 25, 26, 27, 28,
};
static constexpr std::array<uint8_t, 16> qmc2_encv2_key2 = {
    31, 32, 33, 34, 35, 36, 37, 38, 41, 42, 43, 44, 45, 46, 47, 48,
};
#endif
// --- QMC2 Decryption Config

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

    InputFileStream input_stream{input_file};

    // setup crypto
    auto key_crypto = qmc2::CreateKeyCrypto(qmc2_seed, qmc2_encv2_key1.data(), qmc2_encv2_key2.data());
    auto footer_parser = qmc2::CreateQMC2FooterParser(std::move(key_crypto));
    auto footer = footer_parser->Parse(input_stream);
    if (footer->state != qmc2::FooterParseState::OK)
    {
        std::cerr << "could not parse key from file - error(" << static_cast<uint32_t>(footer->state) << ")"
                  << std::endl;
        return 1;
    }

    std::ofstream output_file(argv[2], std::ofstream::binary);
    if (!output_file.is_open())
    {
        std::cerr << "ERROR: could not open output file" << std::endl;
        return 1;
    }

    // Create our transformer
    std::unique_ptr<ITransformer> transformer =
        transformer::CreateQMC2RC4DecryptionTransformer(footer->key.data(), footer->key.size());

    // We need to create a "reader slice" so we don't "over-decrypt" key section.
    SlicedReadableStream reader{input_stream, 0, input_stream.GetSize() - footer->footer_size};
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
