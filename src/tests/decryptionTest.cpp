#include "decryptionModule.h"
#include "simpletest.h"
#include <iostream>
#include <iterator>

using namespace AES;
using namespace std;

DEFINE_TEST(DecrptTestExampleOneRound)
{

    static uint8_t input[4][4] = {
        {0x48, 0x67, 0x4d, 0xd6},
        {0x6c, 0x1d, 0xe3, 0x5f},
        {0x4e, 0x9d, 0xb1, 0x58},
        {0xee, 0x0d, 0x38, 0xe7}};

    static uint8_t input0[4][4] = {
        {0x19, 0xa0, 0x9a, 0xe9},
        {0x3d, 0xf4, 0xc6, 0xf8},
        {0xe3, 0xe2, 0x8d, 0x48},
        {0xbe, 0x2b, 0x2a, 0x08}};


    static uint8_t cipher_key[4][4] = {
        {0x3d, 0x47, 0x1e, 0x6d},
        {0x80, 0x16, 0x23, 0x7a},
        {0x47, 0xfe, 0x7e, 0x88},
        {0x7d, 0x3e, 0x44, 0x3b}};

    static uint8_t cipher_key0[4][4] = {
        {0x2b, 0x28, 0xab, 0x09},
        {0x7e, 0xae, 0xf7, 0xcf},
        {0x15, 0xd2, 0x15, 0x4f},
        {0x16, 0xa6, 0x88, 0x3c}};

    static uint8_t plain_text0[4][4] = {
        {0x32, 0x88, 0x31, 0xe0},
        {0x43, 0x5a, 0x31, 0x37},
        {0xf6, 0x30, 0x98, 0x07},
        {0xa8, 0x8d, 0xa2, 0x34}};


    static uint8_t plain_text[4][4] = {
        {0xaa, 0x61, 0x82, 0x68},
        {0x8f, 0xdd, 0xd2, 0x32},
        {0x5f, 0xe3, 0x4a, 0x46},
        {0x03, 0xef, 0xd2, 0x9a}};

    Decrypt_first_round(input0, cipher_key0);
    TEST_EQ(input0[1][0], 0x43);
    TEST_EQ(input0[0][3], 0xe0);
    TEST_EQ(input0[2][2], 0x98);
    TEST_EQ(input0[3][3], 0x34);


    // Decrypt_one_round(input, cipher_key);
    // TEST_EQ(input[1][0], 0x48);
    // TEST_EQ(input[0][3], 0x68);
    // TEST_EQ(input[2][2], 0x4a);
    // TEST_EQ(input[3][3], 0x9a);
}