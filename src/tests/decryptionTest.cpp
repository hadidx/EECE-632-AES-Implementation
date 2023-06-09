#include "decryptionModule.h"
#include "simpletest.h"
#include <iostream>
#include <iterator>
#include "KeyExpansion.h"
#include "Helpers.h"

using namespace AES;
using namespace std;

DEFINE_TEST(DecrptTestExampleOneRound)
{

    static uint8_t input[4][4] = {
        {0x7a, 0x89, 0x2b, 0x3d},
        {0xd5, 0xef, 0xca, 0x9f},
        {0xfd, 0x4e, 0x10, 0xf5},
        {0xa7, 0x27, 0x0b, 0x9f}};


    static uint8_t cipher_key[4][4] = {
        {0x54, 0xf0, 0x10, 0xbe},
        {0x99, 0x85, 0x93, 0x2c},
        {0x32, 0x57, 0xed, 0x97},
        {0xd1, 0x68, 0x9c, 0x4e}};

    

    Decrypt_one_round(input, cipher_key);
    TEST_EQ(input[0][0], 0x54);
}
    
DEFINE_TEST(DecryptTest128bits)
{

    // static uint8_t state[4][4] = {
    // {0x69, 0x6a, 0xd8, 0x70},
    // {0xc4, 0x7b, 0xcd, 0xb4},
    // {0xe0, 0x04, 0xb7, 0xc5},
    // {0xd8, 0x30, 0x80, 0x5a}};
 
    static uint8_t input[16] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};

    AES::AESMode mode;
    mode = CommonVariables::AES128;
    uint8_t output[4][4];
    cbyte key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}; 
    Decrypt(input, key,  output, mode);  

    TEST_EQ(output[0][0],0x00);
    TEST_EQ(output[0][1],0x44);
    TEST_EQ(output[0][2],0x88);
    TEST_EQ(output[0][3],0xcc);
    TEST_EQ(output[1][0],0x11);
    TEST_EQ(output[1][1],0x55);
    TEST_EQ(output[1][2],0x99);
    TEST_EQ(output[1][3],0xdd);
    TEST_EQ(output[2][0],0x22);
    TEST_EQ(output[2][1],0x66);
    TEST_EQ(output[2][2],0xaa);
    TEST_EQ(output[2][3],0xee);
    TEST_EQ(output[3][0],0x33);
    TEST_EQ(output[3][1],0x77);
    TEST_EQ(output[3][2],0xbb);
    TEST_EQ(output[3][3],0xff);

}


DEFINE_TEST(DecryptTest192bits)
{

    // static uint8_t state[4][4] = {
    // {0xdd, 0x86, 0x6e, 0xec},
    // {0xa9, 0x4c, 0xaf, 0x0d},
    // {0x7c, 0xdf, 0x70, 0x71},
    // {0xa4, 0xe0, 0xa0, 0x91}};

    static uint8_t input[16] = {0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91 };

    AES::AESMode mode;
    mode = CommonVariables::AES192;
    uint8_t output[4][4];
    cbyte key[24] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,0x12,0x13,0x14,0x15,0x16,0x17};
    Decrypt(input, key, output, mode);
    
    TEST_EQ(output[0][0],0x00);

}

DEFINE_TEST(DecryptTest256bits)
{

    // static uint8_t state[4][4] = {
    // {0x8e, 0x51, 0xea, 0x4b},
    // {0xa2, 0x67, 0xfc, 0x49},
    // {0xb7, 0x45, 0x49, 0x60},
    // {0xca, 0xbf, 0x90, 0x89}};

    
    static uint8_t input[16] = {0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89};


    AES::AESMode mode;
    mode = CommonVariables::AES256;
    uint8_t output[4][4];
    cbyte key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    Decrypt(input, key, output, mode);
    
    TEST_EQ(output[0][0],0x00);

}
