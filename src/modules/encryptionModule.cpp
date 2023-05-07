#include "encryptionModule.h"
#include <iostream>
#include "Helpers.h"
#include "KeyExpansion.h"
#include "RNG.h"

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

void AES::calcMixColmask(uint8_t mask[10])
{
    /*

 mask[6] = mul_02[mask[2]] ^ mul_03[mask[3]] ^ mask[4]         ^ mask[5];
  mask[7] = mask[2]         ^ mul_02[mask[3]] ^ mul_03[mask[4]] ^ mask[5];
  mask[8] = mask[2]         ^ mask[3]         ^ mul_02[mask[4]] ^ mul_03[mask[5]];
  mask[9] = mul_03[mask[2]] ^ mask[3]         ^ mask[4]         ^ mul_02[mask[5]];

   

    */
    
    for (int row = 0; row < 4; row++)
    {
        // dot product of row of the column_matrix and the col of the mask [m1,m2,m3,m4]
        for (int col = 0; col < 4; col++)
        {
            uint8_t out[4] = {mask[2], mask[3], mask[4], mask[5]};

            mask[row+6] ^= AES::galoisMul(CommonVariables::column_matrix[row][col], out[col]);
        }
 
    }
}

void AES::remask( uint8_t state[4][4], uint8_t m1, uint8_t m2, uint8_t m3, uint8_t m4, uint8_t m1_prime, uint8_t m2_prime, uint8_t m3_prime, uint8_t m4_prime)
{
  for (int i = 0; i < 4; i++)
  {
    state[i][0] = state[i][0] ^ (m1 ^ m1_prime);
    state[i][1] = state[i][1] ^ (m2 ^ m2_prime);
    state[i][2] = state[i][2] ^ (m3 ^ m3_prime);
    state[i][3] = state[i][3] ^ (m4 ^ m4_prime);
  }
}

void AES::SubBytesMasked(uint8_t state[4][4], cbyte SboxMasked[256])
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      state[j][i] = SboxMasked[(state)[j][i]];
    }
  }
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
            state[i][j] = AES::CommonVariables::S_BOX[state[i][j]];
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

        //define 10 masks m,m',m1,m2,m3,m4,m'1,m'2,m'3,m'4
        cbyte mask[10] ={0};
        
        //Randomly generate the masks m, m', m1 m2 m3 m4
        for (uint8_t i = 0; i < 6; i++)
        {
            genCryptoRN(1, &mask[i]);
        }

       //Calculate m1',m2',m3',m4' from m1,m2,m3,m4
       calcMixColmask(mask);

        // Compute a masked S-box table SboxMasked such that SboxMasked (x xor m) = Sbox(x) xor m'.
        cbyte SboxMasked[256]; 

        for (int i = 0; i < 256; i++)
            {
                SboxMasked[i ^ mask[0]] = AES::CommonVariables::S_BOX[i] ^ mask[1];
            }


        //mask the state from 0 to m'1, m'2, m'3, m'4
        remask(state, 0,0,0,0, mask[6], mask[7], mask[8], mask[9]);


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

        //Mask the key such that the round key operation transforms the masks from m’1, m’2, m’3, m’4 to m.  
        remask(roundKey, mask[0], mask[0], mask[0], mask[0], mask[6], mask[7], mask[8], mask[9]);
        
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

            AES::SubBytesMasked(state, SboxMasked);

            AES::ShiftRows(state);

            if (roundCounter != numRounds)
            {

                // Remask the state to transform masks from m' to m1,m2,m3,m4
                remask(state, mask[1], mask[1], mask[1], mask[1], mask[2], mask[3], mask[4], mask[5]);
                
                // Mix columns transform masks from m1,m2,m3,m4 to m1', m2', m3', m4' 
                // Apply MixColumns in all rounds but the last
                AES::MixColumns(state);

                //Mask the key such that the round key operation transforms the masks from m’1, m’2, m’3, m’4 to m.  
                remask(roundKey, mask[0], mask[0], mask[0], mask[0], mask[6], mask[7], mask[8], mask[9]);
            
                //masks transformed to m 
                AES::AddRoundKey(state, roundKey);

            }

        }

        //Mask the last keyround such that the masks transform from m’ to 0. 
        remask(roundKey, 0, 0,0,0, mask[1], mask[1], mask[1], mask[1]);
            
        AES::AddRoundKey(state, roundKey);

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