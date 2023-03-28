#include "encryptionModule.h"
#include "simpletest.h"
#include <iostream>
#include <iterator>
#include <iostream>


using namespace AES;
using namespace std;


DEFINE_TEST(EncryptTestExampleOneRound)
{

    static uint8_t input[4][4] = {
        {0x32, 0x88, 0x31, 0xe0},
        {0x43, 0x5a, 0x31, 0x37},
        {0xf6, 0x30, 0x98, 0x07},
        {0xa8, 0x8d, 0xa2, 0x34}};

    static uint8_t cipher_key [4][4]= {
        {0x2b, 0x28, 0xab, 0x09},
        {0x7e, 0xae, 0xf7, 0xcf},
        {0x15, 0xd2, 0x15, 0x4f},
        {0x16, 0xa6, 0x88, 0x3c}};

    static uint8_t cipher_text [4][4]= {
        {0x04, 0xe0, 0x48, 0x28},
        {0x66, 0xcb, 0xf8, 0x06},
        {0x81, 0x19, 0xd3, 0x26},
        {0xe5, 0x9a, 0x7a, 0x4c}};

    uint8_t output[4][4] = {AES::Encrypt_one_round(input, cipher_key)}; 

    TEST_EQ(output[0][0],0x04);
    TEST_EQ(output[0][3],0x28);
    TEST_EQ(output[2][2],0xd3);
    TEST_EQ(output[3][3],0x4c);    

    //bool equal = std::equal(std::begin(output), std::end(output), std::begin(cipher_text));
    

     
/*   if (equal) {
        std::cout << "Encryption Test SUCCEDDED!" << std::endl;
    } else {
        std::cout << "Encryption Test Failed!" << std::endl;
    }
*/
}

