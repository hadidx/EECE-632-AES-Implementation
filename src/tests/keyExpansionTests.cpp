#include "Helpers.h"
#include "KeyExpansion.h"
#include "simpletest.h"

using namespace AES;


DEFINE_TEST(RotWordTest)
{
    cbyte w[4] = {0, 1, 2, 3};
    RotWord(w);
    TEST_EQ(w[0],1);
    TEST_EQ(w[1],2);
    TEST_EQ(w[2],3);
    TEST_EQ(w[3],0);
}

DEFINE_TEST(SubWordTest)
{
    cbyte w[4] = {0x53, 0xf0, 0x01, 0x26};
    SubWord(w);
    TEST_EQ(w[0],0xed);
    TEST_EQ(w[1],0x8c);
    TEST_EQ(w[2],0x7c);
    TEST_EQ(w[3],0xf7);
}

DEFINE_TEST(XORRCONTEST)
{
    cbyte w[4] = {0x53, 0xf0, 0x01, 0x26};
    xorRcon(w,1);
    TEST_EQ(w[0],0x53^0x01);
    TEST_EQ(w[1],0xf0^0x00);
    TEST_EQ(w[2],0x01^0x00);
    TEST_EQ(w[3],0x26^0x00);
}

DEFINE_TEST(AES128Bit)
{
    AES::AESMode mode;
    mode = CommonVariables::AES128;
    cbyte key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

    word* expandeKey = initializeExpandedKey(mode.Nr);
    AES::keyExpansion(key, expandeKey, mode);
    TEST_EQ(expandeKey[43][0],0xb6);
    TEST_EQ(expandeKey[43][1],0x63);
    TEST_EQ(expandeKey[43][2],0x0c);
    TEST_EQ(expandeKey[43][3],0xa6);
    unlockExpandedKeyMemory(expandeKey, mode);
    clearExpandedKeyMem(expandeKey, mode);
}

DEFINE_TEST(AES192Bit)
{
    AES::AESMode mode;
    mode = CommonVariables::AES192;
    cbyte key[24] = {0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b};

    word* expandeKey = initializeExpandedKey(mode.Nr);
    AES::keyExpansion(key, expandeKey, mode);
    TEST_EQ(expandeKey[51][0],0x01);
    TEST_EQ(expandeKey[51][1],0x00);
    TEST_EQ(expandeKey[51][2],0x22);
    TEST_EQ(expandeKey[51][3],0x02);
    unlockExpandedKeyMemory(expandeKey, mode);
    clearExpandedKeyMem(expandeKey, mode);
}


DEFINE_TEST(AES256Bit)
{
    AES::AESMode mode;
    mode = CommonVariables::AES256;
    cbyte key[32] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};

    word* expandeKey = initializeExpandedKey(mode.Nr);
    AES::keyExpansion(key, expandeKey, mode);
    TEST_EQ(expandeKey[59][0],0x70);
    TEST_EQ(expandeKey[59][1],0x6c);
    TEST_EQ(expandeKey[59][2],0x63);
    TEST_EQ(expandeKey[59][3],0x1e);
    unlockExpandedKeyMemory(expandeKey, mode);
    clearExpandedKeyMem(expandeKey, mode);
}