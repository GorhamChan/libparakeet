#include "parakeet-crypto/ITransformer.h"
#include "parakeet-crypto/transformer/ximalaya.h"
#include "test/read_fixture.test.hh"
#include "test/test_decryption.test.hh"

#include <cstdio>
#include <fstream>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <vector>

using namespace parakeet_crypto;

// NOLINTBEGIN(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)

#pragma region Ximalaya Scramble Key
static std::array<uint16_t, transformer::kXimalayaScrambleKeyLen> kTestScrambleKey{
    0x1be, 0x061, 0x193, 0x14e, 0x0cb, 0x1d6, 0x0ae, 0x1a9, 0x2ec, 0x2b5, 0x121, 0x143, 0x3d3, 0x164, 0x02c, 0x07c,
    0x3a1, 0x242, 0x11c, 0x01e, 0x062, 0x063, 0x37c, 0x3fe, 0x0a7, 0x29c, 0x350, 0x32a, 0x03b, 0x099, 0x0d3, 0x047,
    0x03d, 0x0d0, 0x186, 0x0d2, 0x344, 0x07e, 0x0d8, 0x375, 0x1b6, 0x27a, 0x011, 0x22a, 0x1cf, 0x10e, 0x218, 0x1ec,
    0x0ef, 0x054, 0x163, 0x070, 0x2fd, 0x3b8, 0x27b, 0x370, 0x3fd, 0x37e, 0x200, 0x252, 0x2d5, 0x1b4, 0x358, 0x171,
    0x19b, 0x3f8, 0x260, 0x2c6, 0x2b8, 0x3d4, 0x3e2, 0x031, 0x117, 0x33a, 0x28d, 0x0b1, 0x006, 0x08d, 0x312, 0x042,
    0x0a2, 0x0c7, 0x13c, 0x28e, 0x0da, 0x34e, 0x2e0, 0x0b6, 0x066, 0x039, 0x2e9, 0x2bf, 0x144, 0x1af, 0x326, 0x3c7,
    0x265, 0x22e, 0x235, 0x087, 0x1a6, 0x158, 0x152, 0x264, 0x1bb, 0x153, 0x0b2, 0x0aa, 0x09c, 0x2c4, 0x116, 0x115,
    0x005, 0x0e2, 0x0c0, 0x160, 0x13a, 0x088, 0x175, 0x372, 0x0bf, 0x049, 0x24e, 0x3e0, 0x1e4, 0x169, 0x28a, 0x0a3,
    0x30e, 0x346, 0x331, 0x227, 0x3ec, 0x09e, 0x1f0, 0x1a1, 0x0b3, 0x255, 0x0b5, 0x0fc, 0x2cd, 0x349, 0x091, 0x0af,
    0x19c, 0x229, 0x0f9, 0x2c2, 0x136, 0x244, 0x3ae, 0x397, 0x0d6, 0x113, 0x27f, 0x32e, 0x09b, 0x38c, 0x29e, 0x1e6,
    0x141, 0x378, 0x0bb, 0x079, 0x3f5, 0x1fb, 0x3db, 0x1c5, 0x2a5, 0x1e5, 0x0b9, 0x1b3, 0x139, 0x1f3, 0x11b, 0x017,
    0x10d, 0x180, 0x075, 0x1b1, 0x2bd, 0x109, 0x083, 0x104, 0x02a, 0x390, 0x183, 0x2a4, 0x3c6, 0x124, 0x3d7, 0x140,
    0x1c8, 0x128, 0x0d1, 0x19f, 0x036, 0x395, 0x3e8, 0x233, 0x191, 0x021, 0x274, 0x174, 0x384, 0x2d8, 0x076, 0x1c7,
    0x1ac, 0x26b, 0x230, 0x173, 0x0f0, 0x0ff, 0x294, 0x3ad, 0x15a, 0x040, 0x2a1, 0x04d, 0x20a, 0x3ab, 0x03f, 0x238,
    0x25f, 0x11e, 0x12a, 0x1e1, 0x209, 0x0b8, 0x05e, 0x12f, 0x1dc, 0x33e, 0x003, 0x1e8, 0x3a5, 0x135, 0x30a, 0x301,
    0x147, 0x2ad, 0x05c, 0x07b, 0x11d, 0x000, 0x151, 0x2de, 0x3c3, 0x273, 0x10f, 0x2ea, 0x36b, 0x3cf, 0x12d, 0x2e4,
    0x2d2, 0x197, 0x39a, 0x067, 0x177, 0x15e, 0x2d7, 0x270, 0x0ba, 0x157, 0x2eb, 0x15f, 0x1a0, 0x1df, 0x3d0, 0x3cc,
    0x20f, 0x007, 0x267, 0x1bc, 0x211, 0x068, 0x387, 0x34a, 0x266, 0x001, 0x2cb, 0x024, 0x26e, 0x243, 0x27e, 0x29d,
    0x1b7, 0x165, 0x178, 0x275, 0x3b5, 0x15c, 0x1f4, 0x2c5, 0x0dd, 0x32d, 0x288, 0x21a, 0x0f1, 0x219, 0x1c3, 0x1de,
    0x290, 0x1b2, 0x3df, 0x226, 0x125, 0x159, 0x20d, 0x32b, 0x138, 0x323, 0x237, 0x1d4, 0x245, 0x17e, 0x185, 0x39b,
    0x105, 0x2ac, 0x1ce, 0x1c0, 0x148, 0x1bf, 0x14a, 0x2f3, 0x37a, 0x13f, 0x2b9, 0x26f, 0x16d, 0x223, 0x1d3, 0x018,
    0x297, 0x126, 0x21c, 0x1d8, 0x320, 0x3b1, 0x3a6, 0x10b, 0x206, 0x055, 0x2e1, 0x2ff, 0x196, 0x1e0, 0x0f8, 0x2c0,
    0x224, 0x24c, 0x19a, 0x1fa, 0x194, 0x198, 0x1ff, 0x1cd, 0x343, 0x010, 0x092, 0x3aa, 0x369, 0x1f9, 0x00d, 0x3e4,
    0x2ed, 0x2ef, 0x08e, 0x2be, 0x0be, 0x364, 0x02f, 0x093, 0x276, 0x0c2, 0x1fc, 0x23c, 0x06f, 0x268, 0x069, 0x2ba,
    0x01c, 0x2f7, 0x10a, 0x28f, 0x2d1, 0x120, 0x002, 0x1ad, 0x2b1, 0x04a, 0x2ce, 0x29a, 0x015, 0x108, 0x137, 0x162,
    0x18f, 0x1b0, 0x3af, 0x299, 0x15d, 0x103, 0x38a, 0x0e8, 0x2d0, 0x0f4, 0x060, 0x39c, 0x210, 0x394, 0x06a, 0x17b,
    0x2fb, 0x0c9, 0x1e7, 0x2a7, 0x30f, 0x269, 0x181, 0x251, 0x337, 0x025, 0x26c, 0x3c4, 0x09d, 0x1b5, 0x1ca, 0x0fb,
    0x213, 0x26d, 0x1c9, 0x3da, 0x3e1, 0x25d, 0x3c5, 0x1ab, 0x33b, 0x3fb, 0x31a, 0x398, 0x3a0, 0x038, 0x3e3, 0x1d7,
    0x05a, 0x2f4, 0x22d, 0x356, 0x0db, 0x352, 0x18c, 0x0dc, 0x277, 0x253, 0x3bb, 0x129, 0x2a9, 0x0b4, 0x3a4, 0x25e,
    0x094, 0x06c, 0x2a0, 0x3be, 0x36d, 0x0fa, 0x283, 0x34d, 0x0a9, 0x24f, 0x399, 0x282, 0x1e3, 0x340, 0x391, 0x199,
    0x32f, 0x056, 0x329, 0x0d4, 0x220, 0x1b8, 0x13e, 0x016, 0x3c0, 0x149, 0x21d, 0x0ee, 0x35f, 0x347, 0x314, 0x3f4,
    0x3f0, 0x377, 0x24a, 0x12c, 0x39e, 0x208, 0x217, 0x34c, 0x0a5, 0x050, 0x31d, 0x232, 0x296, 0x1a4, 0x240, 0x254,
    0x22b, 0x05f, 0x2b2, 0x2b3, 0x2f1, 0x1dd, 0x084, 0x0ea, 0x2e6, 0x310, 0x2ca, 0x03c, 0x0c6, 0x315, 0x234, 0x1d1,
    0x07a, 0x16f, 0x0c1, 0x2c1, 0x086, 0x2cc, 0x1db, 0x073, 0x3e5, 0x1cb, 0x365, 0x28b, 0x190, 0x00b, 0x3f6, 0x3ef,
    0x0e7, 0x362, 0x172, 0x309, 0x2d6, 0x02e, 0x18a, 0x114, 0x0f5, 0x325, 0x1ae, 0x29b, 0x335, 0x3d6, 0x00a, 0x17f,
    0x01f, 0x2f6, 0x37f, 0x3bf, 0x1e9, 0x19e, 0x132, 0x22c, 0x285, 0x3d9, 0x249, 0x25a, 0x167, 0x046, 0x00f, 0x08b,
    0x20b, 0x324, 0x17a, 0x195, 0x176, 0x029, 0x013, 0x037, 0x0f3, 0x12e, 0x2d3, 0x1fe, 0x35d, 0x279, 0x212, 0x0a0,
    0x3a9, 0x3e7, 0x1c6, 0x374, 0x00c, 0x3ac, 0x259, 0x150, 0x298, 0x1bd, 0x228, 0x24b, 0x317, 0x2b7, 0x35a, 0x388,
    0x101, 0x0ed, 0x019, 0x0b7, 0x376, 0x2d9, 0x133, 0x05d, 0x311, 0x239, 0x250, 0x225, 0x16b, 0x034, 0x188, 0x07d,
    0x207, 0x053, 0x38d, 0x353, 0x2e8, 0x1ee, 0x03e, 0x08c, 0x102, 0x041, 0x15b, 0x18b, 0x0a4, 0x179, 0x2c7, 0x0f7,
    0x096, 0x0cf, 0x339, 0x06b, 0x321, 0x004, 0x0df, 0x2a2, 0x052, 0x18d, 0x2bc, 0x2f5, 0x348, 0x09a, 0x17d, 0x306,
    0x182, 0x2d4, 0x09f, 0x111, 0x330, 0x0fe, 0x08f, 0x1c2, 0x0e0, 0x3f9, 0x2c9, 0x0bc, 0x032, 0x2e2, 0x123, 0x30c,
    0x21e, 0x074, 0x3bc, 0x1ed, 0x305, 0x261, 0x118, 0x04b, 0x3b7, 0x363, 0x100, 0x263, 0x0a8, 0x0ac, 0x286, 0x051,
    0x202, 0x3dd, 0x322, 0x37d, 0x33d, 0x302, 0x2fe, 0x085, 0x2e5, 0x01d, 0x392, 0x1a7, 0x0d7, 0x1da, 0x2a6, 0x044,
    0x222, 0x11a, 0x24d, 0x345, 0x23d, 0x262, 0x030, 0x2c3, 0x3d2, 0x0e3, 0x3c9, 0x3cb, 0x035, 0x36a, 0x0e5, 0x308,
    0x3b3, 0x022, 0x1fd, 0x1b9, 0x1a3, 0x1d0, 0x1c4, 0x0c5, 0x014, 0x127, 0x300, 0x1aa, 0x361, 0x3f1, 0x389, 0x3cd,
    0x3ba, 0x34b, 0x2e3, 0x1a8, 0x231, 0x21f, 0x0e6, 0x027, 0x30b, 0x0fd, 0x1ea, 0x37b, 0x0a1, 0x2b0, 0x381, 0x08a,
    0x383, 0x3b0, 0x31e, 0x34f, 0x2ae, 0x112, 0x23b, 0x14f, 0x0ab, 0x3d8, 0x351, 0x122, 0x221, 0x1d5, 0x0e9, 0x0de,
    0x328, 0x1f6, 0x39f, 0x145, 0x166, 0x064, 0x02d, 0x2cf, 0x36e, 0x382, 0x2c8, 0x184, 0x21b, 0x0ca, 0x33f, 0x2ab,
    0x058, 0x272, 0x2aa, 0x3ce, 0x0f2, 0x00e, 0x33c, 0x304, 0x2f0, 0x2f9, 0x0e1, 0x1f8, 0x161, 0x36f, 0x360, 0x2da,
    0x35b, 0x359, 0x319, 0x072, 0x01a, 0x0bd, 0x033, 0x0b0, 0x23e, 0x247, 0x3b6, 0x354, 0x012, 0x18e, 0x2db, 0x2b4,
    0x3c8, 0x3fc, 0x07f, 0x342, 0x287, 0x341, 0x0c8, 0x0e4, 0x280, 0x3a8, 0x257, 0x048, 0x367, 0x008, 0x256, 0x2f2,
    0x023, 0x0d5, 0x098, 0x3fa, 0x289, 0x0f6, 0x1f1, 0x119, 0x39d, 0x1a5, 0x25b, 0x0cc, 0x107, 0x236, 0x12b, 0x059,
    0x1c1, 0x077, 0x258, 0x355, 0x295, 0x293, 0x14c, 0x1eb, 0x3ed, 0x130, 0x01b, 0x19d, 0x284, 0x334, 0x373, 0x204,
    0x38b, 0x04f, 0x26a, 0x16a, 0x29f, 0x379, 0x1a2, 0x332, 0x271, 0x2fc, 0x1e2, 0x25c, 0x06e, 0x2f8, 0x3a2, 0x043,
    0x009, 0x318, 0x2ee, 0x3b4, 0x2e7, 0x27d, 0x338, 0x246, 0x3b2, 0x3f3, 0x0ce, 0x14b, 0x028, 0x187, 0x156, 0x045,
    0x313, 0x3b9, 0x3dc, 0x1ef, 0x142, 0x30d, 0x189, 0x336, 0x3a3, 0x057, 0x31f, 0x2df, 0x1f5, 0x097, 0x1ba, 0x214,
    0x2a3, 0x155, 0x386, 0x380, 0x307, 0x082, 0x215, 0x078, 0x203, 0x2b6, 0x1f7, 0x3ee, 0x06d, 0x0eb, 0x170, 0x31c,
    0x327, 0x201, 0x14d, 0x371, 0x3ca, 0x0ad, 0x333, 0x02b, 0x36c, 0x13b, 0x05b, 0x248, 0x0c4, 0x04c, 0x11f, 0x316,
    0x3bd, 0x131, 0x3de, 0x17c, 0x04e, 0x1d9, 0x192, 0x090, 0x3d5, 0x216, 0x31b, 0x2a8, 0x2af, 0x3e6, 0x35e, 0x168,
    0x2dc, 0x23f, 0x38e, 0x0d9, 0x291, 0x368, 0x28c, 0x146, 0x16c, 0x3c2, 0x020, 0x154, 0x23a, 0x1d2, 0x27c, 0x3ff,
    0x3e9, 0x278, 0x071, 0x3ea, 0x3c1, 0x1f2, 0x3d1, 0x396, 0x10c, 0x089, 0x03a, 0x241, 0x35c, 0x095, 0x32c, 0x2fa,
    0x110, 0x366, 0x3f7, 0x303, 0x38f, 0x385, 0x0c3, 0x0ec, 0x065, 0x0cd, 0x3a7, 0x20e, 0x026, 0x22f, 0x357, 0x292,
    0x081, 0x134, 0x13d, 0x080, 0x20c, 0x393, 0x2bb, 0x2dd, 0x281, 0x106, 0x3f2, 0x0a6, 0x1cc, 0x16e, 0x3eb, 0x205};
#pragma endregion

TEST(Ximalaya, X2MDecryption)
{
    std::array<uint8_t, 4> content_key = {0x9A, 0x5A, 0xD5, 0x06};
    auto transformer = transformer::CreateXimalayaDecryptionTransformer(kTestScrambleKey.data(), content_key.data(),
                                                                        content_key.size());
    test::should_decrypt_to_fixture("test_xmly.x2m", transformer);
}

TEST(Ximalaya, X3MDecryption)
{
    std::array<uint8_t, 32> content_key = {0x59, 0x02, 0x06, 0xD9, 0xCA, 0xAC, 0xD2, 0xD3, 0x73, 0xCD, 0xBC,
                                           0x1A, 0xB5, 0x97, 0x9A, 0xC4, 0x57, 0xAB, 0x4E, 0x21, 0x13, 0xF3,
                                           0x7C, 0x7A, 0x26, 0xA5, 0xAC, 0x8B, 0xFC, 0x50, 0xFE, 0x97};
    auto transformer = transformer::CreateXimalayaDecryptionTransformer(kTestScrambleKey.data(), content_key.data(),
                                                                        content_key.size());
    test::should_decrypt_to_fixture("test_xmly.x3m", transformer);
}
// NOLINTEND(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)
