#include "encryptionModule.h" 
#include <iostream> 


using namespace std;

using namespace AES;

void AES::AddRoundKey(uint8_t state[4][4], const uint8_t roundKey[4][4])
{
    for (uint8_t i = 0; i < 4; i++)
    {
        for (uint8_t j = 0; j < 4; j++)
        {
            state[i][j] ^= roundKey[i][j];
        }
    }
}

void AES::SubBytes(uint8_t state[4][4])
{
    for (uint8_t i = 0; i < 4; i++)
    {
        for (uint8_t j = 0; j < 4; j++)
        {
            state[i][j] = AES::S_BOX[state[i][j]];
        }
    }
}

void AES::ShiftRows(uint8_t state[4][4])
{
    for (uint8_t i = 0; i < 4; i++)
    {
        if (i > 0)
        {
            uint8_t row [4];
            for (uint8_t j = 0; j < 4; j++)
            {
                row[j] = state[i][j];
            }

            for (uint8_t j = 0; j < 4; j++)
            {
                state[i][j] = row[(i + j) % 4]; 

            }
        }
    }
}

void AES::MixColumns(uint8_t state[4][4])
{
    for (uint8_t i = 0; i < 4; i++)
    {

        uint8_t tmp[4];
        uint8_t multi[4];
        for (uint8_t j = 0; j < 4; j++)
        {
            tmp[j] = state[i][j];
            uint8_t h = (unsigned char)((signed char)state[i][j] >> 7);
            multi[j] = state[i][j] << 1;
            multi[j] ^= 0x1B & h;
        }

        state[i][0] = multi[0] ^ tmp[3] ^ tmp[2] ^ multi[1] ^ tmp[1];
        state[i][1] = multi[1] ^ tmp[0] ^ tmp[3] ^ multi[2] ^ tmp[2];
        state[i][2] = multi[2] ^ tmp[1] ^ tmp[0] ^ multi[3] ^ tmp[3];
        state[i][3] = multi[3] ^ tmp[2] ^ tmp[1] ^ multi[0] ^ tmp[0];
    }
}

uint8_t AES::Encrypt_one_round(uint8_t state[4][4], uint8_t cipher_key[4][4])
{
    AddRoundKey (state, cipher_key);
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);

    return state[4][4];
}

    


