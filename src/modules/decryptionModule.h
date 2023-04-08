#ifndef DECRYPTION_H
#define DECRYPTION_H


#include <stdint.h>
#include <cstring>
#include "Helpers.h"

namespace AES
{
    
        
        uint8_t galoisMul(uint8_t a, uint8_t b);
        void InvAddRoundKey(uint8_t state[4][4], const uint8_t roundKey[4][4]);

        void InvSubBytes(uint8_t state[4][4]);

        void InvShiftRows(uint8_t state[4][4]);

        void InvMixColumns(uint8_t state[4][4]);

         void Decrypt_first_round(uint8_t state[4][4], uint8_t cipher_key[4][4]);

        void Decrypt_one_round(uint8_t state[4][4], uint8_t cipher_key[4][4]);

        void Decrypt(uint8_t input[16], cbyte key[], uint8_t output[4][4], AESMode mode);
    

}

#endif