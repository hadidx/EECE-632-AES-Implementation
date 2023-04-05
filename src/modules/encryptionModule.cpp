#include "encryptionModule.h"
#include <iostream>
#include "Helpers.h"
#include "KeyExpansion.h"

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

void AES::Encrypt(uint8_t state[4][4], cbyte key[], uint8_t output[4][4], AESMode mode) 
    {

        int8_t numRounds = 0;
        /*
        uint8 state [4][4]=
        {   {input[0], input[4], input[8], input[12]},
            {input[1], input[5], input[9], input[13]},
            {input[2], input[6], input[10], input[14]},
            {input[3], input[7], input[11], input[15]}  };
*/
        uint8_t expandedKeyLength = 0;
        numRounds = mode.Nr;

        word* expandedKey = initializeExpandedKey(mode.Nr);

        AES::keyExpansion(key, expandedKey, mode);
        //expanded key is of length nk, expandedkey[0], expandedkey[1],... expandedkey[5] if nk = 6
        // expandedkey[0] is a word of length 4 w[0], w[1], w[2], w[3]
        uint8_t roundKey [4][4]=
        {   {expandedKey[0][0], expandedKey[1][0], expandedKey[2][0], expandedKey[3][0]},
            {expandedKey[0][1], expandedKey[1][1], expandedKey[2][1], expandedKey[3][1]},
            {expandedKey[0][2], expandedKey[1][2], expandedKey[2][2], expandedKey[3][2]},
            {expandedKey[0][3], expandedKey[1][3], expandedKey[2][3], expandedKey[3][3]}};

        AES::AddRoundKey (state, roundKey);

        for (int8_t roundCounter = 1; roundCounter <= numRounds; roundCounter++)
        {
            for (uint8_t i = 0; i < 4; i++)
            {
                for (uint8_t j = 0; j < 4; j++)
                {
                    
                    roundKey[i][j] = expandedKey[roundCounter*4 + j][i];
                }
            }

            AES::SubBytes(state);

            AES::ShiftRows(state);

            if (roundCounter != numRounds)
            {
                // Apply MixColumns in all rounds but the last
                AES::MixColumns(state);
            }

            AES::AddRoundKey(state, roundKey);
        }

        // Copying final state to output
        for (uint8_t i = 0; i < 4; i++)
        {
            for (uint8_t j = 0; j < 4; j++)
            {
                output[i][j] = state[i][j];
            }
        }
    };