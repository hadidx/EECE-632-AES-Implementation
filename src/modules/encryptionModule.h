#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <stdint.h>
#include <cstring>
#include "Helpers.h"


namespace AES
{

    uint8_t galoisMul(uint8_t a, uint8_t b);

    void AddRoundKey (uint8_t state[4][4], const uint8_t roundKey[4][4]);

    void SubBytes (uint8_t state[4][4]);

    void ShiftRows (uint8_t state[4][4]);

    void MixColumns (uint8_t state[4][4]);

    void Encrypt_one_round(uint8_t state[4][4], uint8_t cipher_key[4][4]);

    void Encrypt(uint8_t input[16], cbyte key[], uint8_t output[4][4], AESMode mode);


};

#endif

