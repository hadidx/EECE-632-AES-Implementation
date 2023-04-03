#include "encryptionModule.h"
#include <iostream>
#include "Helpers.h"

using namespace std;

using namespace AES;

uint8_t AES::galoisMul(uint8_t a, uint8_t b)
{

    uint8_t p = 0;

    for (int i = 0; i < 8; i++)
    {
        if (b & 0x01) // if LSB is active (equivalent to a '1' in the polynomial of g2)
        {
            p ^= a; // p += g1 in GF(2^8)
        }

        bool hiBit = (a & 0x80); // g1 >= 128 = 0100 0000
        a <<= 1;                 // rotate g1 left (multiply by x in GF(2^8))
        if (hiBit)
        {
            // must reduce
            a ^= 0x1B; // g1 -= 00011011 == mod(x^8 + x^4 + x^3 + x + 1) = AES irreducible
        }
        b >>= 1; // rotate g2 right (divide by x in GF(2^8))
    }

    return p;
}

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
            uint8_t row[4];
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
    uint8_t out[4][4];

    for (int r = 0; r < 4; r++)
    {
        for (int c = 0; c < 4; c++)
        {
            out[r][c] = 0x00;
            // dot product of row r of the mixColMat and the col c of the state
            for (int i = 0; i < 4; i++)
            {
                out[r][c] ^= AES::galoisMul(CommonVariables::column_matrix[r][i], state[i][c]);
            }
        }
    }

    // copy memory to the state
    memcpy(state, out, 4 * 4 * sizeof(unsigned char));
}

void AES::Encrypt_one_round(uint8_t state[4][4], uint8_t cipher_key[4][4])
{
    AddRoundKey(state, cipher_key);
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
}
