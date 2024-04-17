#include "../../arg_parser.hpp"
#include "parakeet-crypto/qmc2/key_util.h"

#include <cstdint>
#include <memory>
#include <parakeet-crypto/StreamHelper.h>

#include <parakeet-crypto/qmc2/footer_parser.h>
#include <parakeet-crypto/qmc2/key_crypto.h>
#include <parakeet-crypto/transformer/qmc.h>

#include <array>
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

void print_help()
{
    std::cerr << '\n';
    std::cerr << "usage: \n";
    std::cerr << "  -h | --help            Display this usage information\n"
              << "\n"
              << "  -i | --input <path>    Path to input file\n"
              << "  -o | --output <path>   Path to output file\n"
              << "\n"
              << "  --seed <seed>          ekey seed\n"
              << "  --mix-key-1 <key>      [EncV2] mix key 1\n"
              << "  --mix-key-2 <key>      [EncV2] mix key 2\n"
              << "  -k | --ekey [ekey]     EKey of the file (encrypted)\n"
              << "  --raw-ekey [ekey]      Raw ekey to qmc2 decryptor. This overrides '--ekey'.\n"
              << "                         Will attempt to read from file footer if not provided.\n"
              << "\n"
              << "  --tail-trim            Number of bytes to trim off the tail. When key is provided, \n"
              << "                         this will default to 0. When key is absent, this will\n"
              << "                         auto-detect from tail\n"
              << '\n';
}

int main(int argc, char **argv)
{
    using namespace parakeet_crypto;

#if _WIN32
    setlocale(LC_ALL, ".65001");
    _setmode(fileno(stdin), _O_BINARY);
    _setmode(fileno(stdout), _O_BINARY);
    _setmode(fileno(stderr), _O_BINARY);
#endif

    auto o_args = parse_args(argc, argv, {{"i", "input"}, {"o", "output"}, {"k", "ekey"}}, print_help);
    if (!o_args)
    {
        return 1;
    }

    auto args = std::move(*o_args);

    auto path_file_in = args->get_string("input");
    auto path_file_out = args->get_string("output");
    auto ekey_str = args->get_string("ekey");
    auto raw_ekey_str = args->get_string("raw-ekey");

    if (!path_file_in)
    {
        std::cerr << "ERROR: input not specified\n";
        print_help();
        return 2;
    }

    if (!path_file_out)
    {
        std::cerr << "ERROR: output not specified\n";
        print_help();
        return 2;
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

    bool useStdin = *path_file_in == "-";
    std::ifstream input_file;
    if (!useStdin)
    {
        input_file.open(*path_file_in, std::ifstream::binary);
        if (!input_file.is_open())
        {
            std::cerr << "ERROR: could not open input file\n";
            return 1;
        }
    }

    auto input_stream = std::shared_ptr<IReadSeekable>(
        useStdin ? dynamic_cast<IReadSeekable *>(InputMemoryStream::FromStdin().release())
                 : dynamic_cast<IReadSeekable *>(new InputFileStream(input_file)));

    // setup crypto
    auto key_crypto = qmc2::CreateKeyCrypto(seed, qmc2_encv2_key1_local.data(), qmc2_encv2_key2_local.data());

    std::vector<uint8_t> ekey;
    size_t footer_len_exclude{0};
    if (raw_ekey_str)
    {
        footer_len_exclude = 0;
        ekey.assign(raw_ekey_str->begin(), raw_ekey_str->end());
    }
    else if (ekey_str)
    {
        footer_len_exclude = 0;
        ekey = key_crypto->Decrypt(reinterpret_cast<const uint8_t *>(ekey_str->c_str()), // NOLINT(*reinterpret-cast)
                                   ekey_str->size());
    }
    else
    {
        auto footer_parser = qmc2::CreateQMC2FooterParser(std::move(key_crypto));
        auto footer = footer_parser->Parse(*input_stream);
        if (footer->state != qmc2::FooterParseState::OK)
        {
            std::cerr << "could not parse key from file - error(" << static_cast<uint32_t>(footer->state) << ")"
                      << std::endl;
            return 1;
        }
        ekey = footer->key;
        footer_len_exclude = footer->footer_size;
    }
    if (auto footer_exclude_override = args->get_int("tail-trim"))
    {
        footer_len_exclude = *footer_exclude_override;
    }

    bool useStdout = *path_file_out == "-";
    std::ofstream output_file{};
    if (!useStdout)
    {
        output_file.open(*path_file_out, std::ofstream::binary);
        if (!output_file.is_open())
        {
            std::cerr << "ERROR: could not open output file\n";
            return 1;
        }
    }
    auto writer = std::shared_ptr<IWriteable>(useStdin ? dynamic_cast<IWriteable *>(new WriteToStdoutStream())
                                                       : dynamic_cast<IWriteable *>(new OutputFileStream(output_file)));

    // Create our transformer
    auto transformer = (qmc2::GetEncryptionType(ekey) == qmc2::QMC2EncryptionType::RC4)
                           ? transformer::CreateQMC2RC4DecryptionTransformer(ekey)
                           : transformer::CreateQMC2MapDecryptionTransformer(ekey);

    // We need to create a "reader slice" so we don't "over-decrypt" key section.
    SlicedReadableStream reader{*input_stream, 0, input_stream->GetSize() - footer_len_exclude};

    // Perform decryption...
    auto decryption_result = transformer->Transform(&*writer, &reader);
    if (decryption_result != TransformResult::OK)
    {
        std::cerr << "decryption failed - error(" << static_cast<uint32_t>(decryption_result) << ")\n";
        return 1;
    }

    std::cerr << "done!\n";
    return 0;
}

// NOLINTEND(*-magic-numbers)
