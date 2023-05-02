#include "encryptionModule.h"
#include <iostream>
#include "Helpers.h"
#include "KeyExpansion.h"

using namespace std;

using namespace AES;

uint8_t AES::galoisMul(uint8_t a, uint8_t b)
{

    uint8_t product = 0;

    for (int i = 0; i < 8; i++)
    {

        int isLSBActive = (b & 0x01) != 0;
        uint8_t LSBActiveMask = 0xFF*isLSBActive; 
        product ^= (a & LSBActiveMask); //if least significant of b is present, then we add all elements of a to the product
 
        int isMSBActive = (a & 0x80) != 0;
        uint8_t MSBActiveMask = 0xFF*isMSBActive;
        a <<= 1; // multiply a by x in GF(2^8)

        a ^= (0x1B & MSBActiveMask); // if MSB of a is active and we multiply by x => power greater than 7 then reduce by subtracting x^8 = x^4 + x^3 + x + 1
        b >>= 1; // divide b by x in GF(2^8)
    }

    return product;
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
            state[i][j] = AES::sBoxInterpolation(state[i][j]);
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
            // dot product of row r of the column_matrix and the col c of the state
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

void AES::Encrypt(uint8_t input[16], cbyte key[], uint8_t output[4][4], AESMode mode) 
    {

        cbyte state[4][4];

        AES::copyToState(input, state);

        int8_t numRounds = 0;
        uint8_t expandedKeyLength = 0;
        numRounds = mode.Nr;

        word* expandedKey = initializeExpandedKey(mode.Nr);

        AES::lockExpandedKeyMemory(expandedKey, mode);

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
        AES::unlockExpandedKeyMemory(expandedKey, mode);
        AES::clearExpandedKeyMem(expandedKey, mode);
        for (uint8_t i = 0; i < 4; i++)
        {
            for (uint8_t j = 0; j < 4; j++)
            {
                output[i][j] = state[i][j];
            }
        }
    };