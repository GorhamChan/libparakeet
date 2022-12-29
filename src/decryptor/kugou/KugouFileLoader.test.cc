#include "test/helper.test.hh"

#include <span>
#include <vector>
#include "KugouHeader.h"
#include "parakeet-crypto/decryptor/kugou/KugouFileLoader.h"

using namespace parakeet_crypto::decryptor::kugou;
using namespace parakeet_crypto::decryptor;
using namespace parakeet_crypto;

static const uint8_t kgm_header_v2[64] = {0x7C, 0xD5, 0x32, 0xEB, 0x86, 0x02, 0x7F, 0x4B, 0xA8, 0xAF, 0xA6, 0x8E, 0x0F,
                                          0xFF, 0x99, 0x14, 0x00, 0x04, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00,
                                          0x00, 0x00, 0x88, 0x7C, 0x6C, 0x48, 0xD9, 0x06, 0x29, 0x76, 0xB3, 0x9A, 0x20,
                                          0xAB, 0x46, 0x09, 0x9C, 0xCD, 0x5B, 0x44, 0x65, 0x63, 0x72, 0x79, 0x70, 0x74,
                                          0x6F, 0x72, 0x54, 0x65, 0x73, 0x74, 0x44, 0x5D, 0x00, 0x00, 0x00, 0x00};

static const uint8_t kgm_header_v3[64] = {0x7C, 0xD5, 0x32, 0xEB, 0x86, 0x02, 0x7F, 0x4B, 0xA8, 0xAF, 0xA6, 0x8E, 0x0F,
                                          0xFF, 0x99, 0x14, 0x00, 0x04, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00,
                                          0x00, 0x00, 0x42, 0x78, 0xDD, 0xDF, 0x3D, 0x32, 0x38, 0xCA, 0x2F, 0xFB, 0x17,
                                          0xB1, 0x05, 0xA4, 0x9F, 0x12, 0x5B, 0x44, 0x65, 0x63, 0x72, 0x79, 0x70, 0x74,
                                          0x6F, 0x72, 0x54, 0x65, 0x73, 0x74, 0x44, 0x5D, 0x00, 0x00, 0x00, 0x00};

static const uint8_t kgm_header_v4[64] = {0x7C, 0xD5, 0x32, 0xEB, 0x86, 0x02, 0x7F, 0x4B, 0xA8, 0xAF, 0xA6, 0x8E, 0x0F,
                                          0xFF, 0x99, 0x14, 0x00, 0x04, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00,
                                          0x00, 0x00, 0x7E, 0xC4, 0x1F, 0xD1, 0x85, 0xFA, 0x1E, 0x0E, 0x4D, 0xAA, 0xDB,
                                          0xF6, 0xF2, 0x7D, 0x32, 0x34, 0x5B, 0x44, 0x65, 0x63, 0x72, 0x79, 0x70, 0x74,
                                          0x69, 0x6F, 0x6E, 0x20, 0x4B, 0x65, 0x79, 0x5D, 0x00, 0x00, 0x00, 0x00};

static const uint8_t kgm_key_slot_1_key[] = {'0', '9', 'A', 'Z'};

unsigned char kgm_v4_file_key_table[705] = {
    0x4C, 0x6F, 0x72, 0x65, 0x6D, 0x20, 0x69, 0x70, 0x73, 0x75, 0x6D, 0x20, 0x64, 0x6F, 0x6C, 0x6F, 0x72, 0x20, 0x73,
    0x69, 0x74, 0x20, 0x61, 0x6D, 0x65, 0x74, 0x2C, 0x20, 0x63, 0x6F, 0x6E, 0x73, 0x65, 0x63, 0x74, 0x65, 0x74, 0x75,
    0x72, 0x20, 0x61, 0x64, 0x69, 0x70, 0x69, 0x73, 0x63, 0x69, 0x6E, 0x67, 0x20, 0x65, 0x6C, 0x69, 0x74, 0x2E, 0x20,
    0x4E, 0x75, 0x6C, 0x6C, 0x61, 0x6D, 0x20, 0x6D, 0x61, 0x78, 0x69, 0x6D, 0x75, 0x73, 0x20, 0x69, 0x61, 0x63, 0x75,
    0x6C, 0x69, 0x73, 0x20, 0x6E, 0x75, 0x6C, 0x6C, 0x61, 0x20, 0x73, 0x65, 0x64, 0x20, 0x66, 0x72, 0x69, 0x6E, 0x67,
    0x69, 0x6C, 0x6C, 0x61, 0x2E, 0x20, 0x53, 0x65, 0x64, 0x20, 0x6E, 0x65, 0x71, 0x75, 0x65, 0x20, 0x6C, 0x65, 0x6F,
    0x2C, 0x20, 0x73, 0x6F, 0x64, 0x61, 0x6C, 0x65, 0x73, 0x20, 0x61, 0x74, 0x20, 0x6C, 0x69, 0x67, 0x75, 0x6C, 0x61,
    0x20, 0x69, 0x64, 0x2C, 0x20, 0x70, 0x72, 0x65, 0x74, 0x69, 0x75, 0x6D, 0x20, 0x62, 0x69, 0x62, 0x65, 0x6E, 0x64,
    0x75, 0x6D, 0x20, 0x61, 0x75, 0x67, 0x75, 0x65, 0x2E, 0x20, 0x41, 0x6C, 0x69, 0x71, 0x75, 0x61, 0x6D, 0x20, 0x76,
    0x65, 0x68, 0x69, 0x63, 0x75, 0x6C, 0x61, 0x20, 0x65, 0x72, 0x6F, 0x73, 0x20, 0x6E, 0x6F, 0x6E, 0x20, 0x6E, 0x75,
    0x6E, 0x63, 0x20, 0x6D, 0x61, 0x74, 0x74, 0x69, 0x73, 0x20, 0x66, 0x61, 0x75, 0x63, 0x69, 0x62, 0x75, 0x73, 0x2E,
    0x20, 0x53, 0x65, 0x64, 0x20, 0x65, 0x67, 0x65, 0x74, 0x20, 0x6D, 0x69, 0x20, 0x76, 0x69, 0x74, 0x61, 0x65, 0x20,
    0x65, 0x78, 0x20, 0x67, 0x72, 0x61, 0x76, 0x69, 0x64, 0x61, 0x20, 0x72, 0x75, 0x74, 0x72, 0x75, 0x6D, 0x2E, 0x20,
    0x44, 0x75, 0x69, 0x73, 0x20, 0x76, 0x69, 0x74, 0x61, 0x65, 0x20, 0x66, 0x65, 0x6C, 0x69, 0x73, 0x20, 0x65, 0x74,
    0x20, 0x74, 0x75, 0x72, 0x70, 0x69, 0x73, 0x20, 0x69, 0x6E, 0x74, 0x65, 0x72, 0x64, 0x75, 0x6D, 0x20, 0x62, 0x6C,
    0x61, 0x6E, 0x64, 0x69, 0x74, 0x2E, 0x20, 0x4E, 0x75, 0x6C, 0x6C, 0x61, 0x6D, 0x20, 0x76, 0x69, 0x74, 0x61, 0x65,
    0x20, 0x65, 0x73, 0x74, 0x20, 0x69, 0x6E, 0x74, 0x65, 0x72, 0x64, 0x75, 0x6D, 0x2C, 0x20, 0x6F, 0x72, 0x6E, 0x61,
    0x72, 0x65, 0x20, 0x64, 0x69, 0x61, 0x6D, 0x20, 0x73, 0x69, 0x74, 0x20, 0x61, 0x6D, 0x65, 0x74, 0x2C, 0x20, 0x64,
    0x69, 0x67, 0x6E, 0x69, 0x73, 0x73, 0x69, 0x6D, 0x20, 0x61, 0x72, 0x63, 0x75, 0x2E, 0x20, 0x44, 0x6F, 0x6E, 0x65,
    0x63, 0x20, 0x6D, 0x6F, 0x6C, 0x65, 0x73, 0x74, 0x69, 0x65, 0x20, 0x76, 0x65, 0x6E, 0x65, 0x6E, 0x61, 0x74, 0x69,
    0x73, 0x20, 0x73, 0x63, 0x65, 0x6C, 0x65, 0x72, 0x69, 0x73, 0x71, 0x75, 0x65, 0x2E, 0x20, 0x44, 0x75, 0x69, 0x73,
    0x20, 0x66, 0x69, 0x6E, 0x69, 0x62, 0x75, 0x73, 0x20, 0x6D, 0x61, 0x6C, 0x65, 0x73, 0x75, 0x61, 0x64, 0x61, 0x20,
    0x64, 0x6F, 0x6C, 0x6F, 0x72, 0x20, 0x73, 0x65, 0x64, 0x20, 0x69, 0x61, 0x63, 0x75, 0x6C, 0x69, 0x73, 0x2E, 0x20,
    0x51, 0x75, 0x69, 0x73, 0x71, 0x75, 0x65, 0x20, 0x6D, 0x61, 0x78, 0x69, 0x6D, 0x75, 0x73, 0x20, 0x6E, 0x69, 0x62,
    0x68, 0x20, 0x6D, 0x61, 0x75, 0x72, 0x69, 0x73, 0x2C, 0x20, 0x61, 0x20, 0x64, 0x61, 0x70, 0x69, 0x62, 0x75, 0x73,
    0x20, 0x6D, 0x69, 0x20, 0x72, 0x68, 0x6F, 0x6E, 0x63, 0x75, 0x73, 0x20, 0x72, 0x68, 0x6F, 0x6E, 0x63, 0x75, 0x73,
    0x2E, 0x20, 0x50, 0x65, 0x6C, 0x6C, 0x65, 0x6E, 0x74, 0x65, 0x73, 0x71, 0x75, 0x65, 0x20, 0x68, 0x61, 0x62, 0x69,
    0x74, 0x61, 0x6E, 0x74, 0x20, 0x6D, 0x6F, 0x72, 0x62, 0x69, 0x20, 0x74, 0x72, 0x69, 0x73, 0x74, 0x69, 0x71, 0x75,
    0x65, 0x20, 0x73, 0x65, 0x6E, 0x65, 0x63, 0x74, 0x75, 0x73, 0x20, 0x65, 0x74, 0x20, 0x6E, 0x65, 0x74, 0x75, 0x73,
    0x20, 0x65, 0x74, 0x20, 0x6D, 0x61, 0x6C, 0x65, 0x73, 0x75, 0x61, 0x64, 0x61, 0x20, 0x66, 0x61, 0x6D, 0x65, 0x73,
    0x20, 0x61, 0x63, 0x20, 0x74, 0x75, 0x72, 0x70, 0x69, 0x73, 0x20, 0x65, 0x67, 0x65, 0x73, 0x74, 0x61, 0x73, 0x2E,
    0x20, 0x55, 0x74, 0x20, 0x74, 0x72, 0x69, 0x73, 0x74, 0x69, 0x71, 0x75, 0x65, 0x20, 0x61, 0x63, 0x20, 0x6E, 0x75,
    0x6C, 0x6C, 0x61, 0x20, 0x73, 0x65, 0x64, 0x20, 0x69, 0x6D, 0x70, 0x65, 0x72, 0x64, 0x69, 0x65, 0x74, 0x2E, 0x20,
    0x41, 0x65, 0x6E, 0x65, 0x61, 0x6E, 0x20, 0x64, 0x69, 0x67, 0x6E, 0x69, 0x73, 0x73, 0x69, 0x6D, 0x20, 0x74, 0x6F,
    0x72, 0x74, 0x6F, 0x72, 0x20, 0x76, 0x65, 0x6C, 0x20, 0x65, 0x78, 0x20, 0x70, 0x6F, 0x72, 0x74, 0x61, 0x2C, 0x20,
    0x61, 0x20, 0x63, 0x6F, 0x6E, 0x76, 0x61, 0x6C, 0x6C, 0x69, 0x73, 0x20, 0x6C, 0x61, 0x63, 0x75, 0x73, 0x20, 0x62,
    0x6C, 0x61, 0x6E, 0x64, 0x69, 0x74, 0x2E, 0x38, 0x39, 0x34, 0x31, 0x36, 0x39, 0x31, 0x32, 0x33, 0x38, 0x33, 0x34,
    0x30, 0x39};

unsigned char kgm_v4_slot_key_table[712] = {
    0x4C, 0x6F, 0x72, 0x65, 0x6D, 0x20, 0x69, 0x70, 0x73, 0x75, 0x6D, 0x20, 0x64, 0x6F, 0x6C, 0x6F, 0x72, 0x20, 0x73,
    0x69, 0x74, 0x20, 0x61, 0x6D, 0x65, 0x74, 0x2C, 0x20, 0x63, 0x6F, 0x6E, 0x73, 0x65, 0x63, 0x74, 0x65, 0x74, 0x75,
    0x72, 0x20, 0x61, 0x64, 0x69, 0x70, 0x69, 0x73, 0x63, 0x69, 0x6E, 0x67, 0x20, 0x65, 0x6C, 0x69, 0x74, 0x2E, 0x20,
    0x53, 0x65, 0x64, 0x20, 0x71, 0x75, 0x69, 0x73, 0x20, 0x6F, 0x72, 0x6E, 0x61, 0x72, 0x65, 0x20, 0x6E, 0x69, 0x62,
    0x68, 0x2E, 0x20, 0x44, 0x6F, 0x6E, 0x65, 0x63, 0x20, 0x76, 0x69, 0x76, 0x65, 0x72, 0x72, 0x61, 0x20, 0x68, 0x65,
    0x6E, 0x64, 0x72, 0x65, 0x72, 0x69, 0x74, 0x20, 0x61, 0x6C, 0x69, 0x71, 0x75, 0x61, 0x6D, 0x2E, 0x20, 0x4D, 0x6F,
    0x72, 0x62, 0x69, 0x20, 0x65, 0x67, 0x65, 0x73, 0x74, 0x61, 0x73, 0x20, 0x70, 0x75, 0x6C, 0x76, 0x69, 0x6E, 0x61,
    0x72, 0x20, 0x6E, 0x65, 0x71, 0x75, 0x65, 0x20, 0x65, 0x74, 0x20, 0x70, 0x65, 0x6C, 0x6C, 0x65, 0x6E, 0x74, 0x65,
    0x73, 0x71, 0x75, 0x65, 0x2E, 0x20, 0x53, 0x75, 0x73, 0x70, 0x65, 0x6E, 0x64, 0x69, 0x73, 0x73, 0x65, 0x20, 0x66,
    0x65, 0x72, 0x6D, 0x65, 0x6E, 0x74, 0x75, 0x6D, 0x20, 0x62, 0x69, 0x62, 0x65, 0x6E, 0x64, 0x75, 0x6D, 0x20, 0x72,
    0x69, 0x73, 0x75, 0x73, 0x20, 0x71, 0x75, 0x69, 0x73, 0x20, 0x66, 0x72, 0x69, 0x6E, 0x67, 0x69, 0x6C, 0x6C, 0x61,
    0x2E, 0x20, 0x44, 0x75, 0x69, 0x73, 0x20, 0x65, 0x75, 0x20, 0x76, 0x69, 0x76, 0x65, 0x72, 0x72, 0x61, 0x20, 0x6D,
    0x61, 0x73, 0x73, 0x61, 0x2E, 0x20, 0x45, 0x74, 0x69, 0x61, 0x6D, 0x20, 0x6E, 0x6F, 0x6E, 0x20, 0x6E, 0x69, 0x73,
    0x69, 0x20, 0x73, 0x65, 0x64, 0x20, 0x72, 0x69, 0x73, 0x75, 0x73, 0x20, 0x64, 0x69, 0x67, 0x6E, 0x69, 0x73, 0x73,
    0x69, 0x6D, 0x20, 0x74, 0x69, 0x6E, 0x63, 0x69, 0x64, 0x75, 0x6E, 0x74, 0x2E, 0x20, 0x50, 0x72, 0x61, 0x65, 0x73,
    0x65, 0x6E, 0x74, 0x20, 0x72, 0x75, 0x74, 0x72, 0x75, 0x6D, 0x20, 0x69, 0x6E, 0x74, 0x65, 0x72, 0x64, 0x75, 0x6D,
    0x20, 0x74, 0x72, 0x69, 0x73, 0x74, 0x69, 0x71, 0x75, 0x65, 0x2E, 0x20, 0x41, 0x6C, 0x69, 0x71, 0x75, 0x61, 0x6D,
    0x20, 0x63, 0x6F, 0x6E, 0x64, 0x69, 0x6D, 0x65, 0x6E, 0x74, 0x75, 0x6D, 0x20, 0x64, 0x69, 0x61, 0x6D, 0x20, 0x76,
    0x65, 0x6C, 0x20, 0x74, 0x72, 0x69, 0x73, 0x74, 0x69, 0x71, 0x75, 0x65, 0x20, 0x66, 0x65, 0x72, 0x6D, 0x65, 0x6E,
    0x74, 0x75, 0x6D, 0x2E, 0x20, 0x4E, 0x75, 0x6E, 0x63, 0x20, 0x75, 0x6C, 0x74, 0x72, 0x69, 0x63, 0x65, 0x73, 0x20,
    0x6C, 0x6F, 0x62, 0x6F, 0x72, 0x74, 0x69, 0x73, 0x20, 0x6E, 0x75, 0x6E, 0x63, 0x20, 0x63, 0x6F, 0x6E, 0x76, 0x61,
    0x6C, 0x6C, 0x69, 0x73, 0x20, 0x63, 0x6F, 0x6D, 0x6D, 0x6F, 0x64, 0x6F, 0x2E, 0x20, 0x51, 0x75, 0x69, 0x73, 0x71,
    0x75, 0x65, 0x20, 0x65, 0x67, 0x65, 0x73, 0x74, 0x61, 0x73, 0x20, 0x6D, 0x65, 0x74, 0x75, 0x73, 0x20, 0x76, 0x69,
    0x74, 0x61, 0x65, 0x20, 0x65, 0x78, 0x20, 0x64, 0x69, 0x63, 0x74, 0x75, 0x6D, 0x2C, 0x20, 0x76, 0x65, 0x6C, 0x20,
    0x66, 0x72, 0x69, 0x6E, 0x67, 0x69, 0x6C, 0x6C, 0x61, 0x20, 0x69, 0x70, 0x73, 0x75, 0x6D, 0x20, 0x6D, 0x61, 0x6C,
    0x65, 0x73, 0x75, 0x61, 0x64, 0x61, 0x2E, 0x20, 0x41, 0x65, 0x6E, 0x65, 0x61, 0x6E, 0x20, 0x61, 0x63, 0x20, 0x6D,
    0x61, 0x74, 0x74, 0x69, 0x73, 0x20, 0x65, 0x73, 0x74, 0x2E, 0x20, 0x46, 0x75, 0x73, 0x63, 0x65, 0x20, 0x65, 0x75,
    0x20, 0x75, 0x6C, 0x74, 0x72, 0x69, 0x63, 0x69, 0x65, 0x73, 0x20, 0x61, 0x75, 0x67, 0x75, 0x65, 0x2E, 0x20, 0x44,
    0x75, 0x69, 0x73, 0x20, 0x65, 0x67, 0x65, 0x74, 0x20, 0x6C, 0x61, 0x6F, 0x72, 0x65, 0x65, 0x74, 0x20, 0x6C, 0x6F,
    0x72, 0x65, 0x6D, 0x2E, 0x20, 0x53, 0x65, 0x64, 0x20, 0x63, 0x6F, 0x6E, 0x67, 0x75, 0x65, 0x20, 0x69, 0x70, 0x73,
    0x75, 0x6D, 0x20, 0x65, 0x67, 0x65, 0x74, 0x20, 0x66, 0x65, 0x72, 0x6D, 0x65, 0x6E, 0x74, 0x75, 0x6D, 0x20, 0x65,
    0x67, 0x65, 0x73, 0x74, 0x61, 0x73, 0x2E, 0x20, 0x50, 0x72, 0x61, 0x65, 0x73, 0x65, 0x6E, 0x74, 0x20, 0x66, 0x61,
    0x75, 0x63, 0x69, 0x62, 0x75, 0x73, 0x20, 0x76, 0x65, 0x68, 0x69, 0x63, 0x75, 0x6C, 0x61, 0x20, 0x6D, 0x61, 0x75,
    0x72, 0x69, 0x73, 0x20, 0x76, 0x69, 0x74, 0x61, 0x65, 0x20, 0x61, 0x75, 0x63, 0x74, 0x6F, 0x72, 0x2E, 0x20, 0x4D,
    0x61, 0x65, 0x63, 0x65, 0x6E, 0x61, 0x73, 0x20, 0x72, 0x75, 0x74, 0x72, 0x75, 0x6D, 0x20, 0x65, 0x6C, 0x69, 0x74,
    0x20, 0x65, 0x75, 0x20, 0x74, 0x75, 0x72, 0x70, 0x69, 0x73, 0x20, 0x6F, 0x72, 0x6E, 0x61, 0x72, 0x65, 0x2C, 0x20,
    0x69, 0x64, 0x20, 0x73, 0x6F, 0x6C, 0x6C, 0x69, 0x63, 0x69, 0x74, 0x75, 0x64, 0x69, 0x6E, 0x20, 0x64, 0x75, 0x69,
    0x20, 0x6D, 0x61, 0x78, 0x69, 0x6D, 0x75, 0x73, 0x2E};

std::unique_ptr<KugouFileLoader> create_test_kgm_decryptor() {
  KugouSlotKeys slot_keys;
  slot_keys[1] = std::vector(&kgm_key_slot_1_key[0], &kgm_key_slot_1_key[sizeof(kgm_key_slot_1_key)]);
  KugouV4SlotKeyExpansionTable v4_slot_key_table(&kgm_v4_slot_key_table[0],
                                                 &kgm_v4_slot_key_table[sizeof(kgm_v4_slot_key_table)]);
  KugouV4FileKeyExpansionTable v4_file_key_table(&kgm_v4_file_key_table[0],
                                                 &kgm_v4_file_key_table[sizeof(kgm_v4_file_key_table)]);
  return KugouFileLoader::Create(slot_keys, v4_slot_key_table, v4_file_key_table);
}

TEST(KugouFileLoader, KGMv2) {
  auto d = create_test_kgm_decryptor();
  ASSERT_TRUE(d->Write(&kgm_header_v2[0], sizeof(kgm_header_v2))) << "should accept our kgm header";
  ASSERT_TRUE(d->End()) << "should end successfully";
}

TEST(KugouFileLoader, KGMv3) {
  auto d = create_test_kgm_decryptor();
  ASSERT_TRUE(d->Write(&kgm_header_v3[0], sizeof(kgm_header_v3))) << "should accept our kgm header";
  ASSERT_TRUE(d->End()) << "should end successfully";
}

TEST(KugouFileLoader, KGMv4) {
  auto d = create_test_kgm_decryptor();
  ASSERT_TRUE(d->Write(&kgm_header_v4[0], sizeof(kgm_header_v4))) << "should accept our kgm header";
  ASSERT_TRUE(d->End()) << "should end successfully";
}
