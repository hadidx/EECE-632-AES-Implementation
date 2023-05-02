#include "decryptionModule.h"
#include <iostream>
#include "encryptionModule.h"
#include "Helpers.h"
#include "KeyExpansion.h"

using namespace std;

using namespace AES;

void AES::InvAddRoundKey(uint8_t state[4][4], const uint8_t roundKey[4][4])
{
    for (uint8_t i = 0; i < 4; i++)
    {
        for (uint8_t j = 0; j < 4; j++)
        {
            state[i][j] ^= roundKey[i][j];
        }
    }
}

void AES::InvSubBytes(uint8_t state[4][4])
{
    for (uint8_t i = 0; i < 4; i++)
    {
        for (uint8_t j = 0; j < 4; j++)
        {
            state[i][j] = AES::sBoxInvInterpolation(state[i][j]);
        }
    }
}


void AES::InvShiftRows(uint8_t state[4][4])
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

            for (int8_t j = 3; j >= 0; j--)
            {
                state[i][j] = row[(j + (4- i)) % 4];
            }
        }
    }
}

void AES::InvMixColumns(uint8_t state[4][4]) {

    uint8_t temp[4][4];
    for (int c = 0; c < 4; c++) {
        temp[0][c] = AES::galoisMul(CommonVariables::Inv_column_matrix[0][0], state[0][c])
                   ^ AES::galoisMul(CommonVariables::Inv_column_matrix[0][1], state[1][c])
                   ^ AES::galoisMul(CommonVariables::Inv_column_matrix[0][2], state[2][c])
                   ^ AES::galoisMul(CommonVariables::Inv_column_matrix[0][3], state[3][c]);
        temp[1][c] = AES::galoisMul(CommonVariables::Inv_column_matrix[1][0], state[0][c])
                   ^ AES::galoisMul(CommonVariables::Inv_column_matrix[1][1], state[1][c])
                   ^ AES::galoisMul(CommonVariables::Inv_column_matrix[1][2], state[2][c])
                   ^ AES::galoisMul(CommonVariables::Inv_column_matrix[1][3], state[3][c]);
        temp[2][c] = AES::galoisMul(CommonVariables::Inv_column_matrix[2][0], state[0][c])
                   ^ AES::galoisMul(CommonVariables::Inv_column_matrix[2][1], state[1][c])
                   ^ AES::galoisMul(CommonVariables::Inv_column_matrix[2][2], state[2][c])
                   ^ AES::galoisMul(CommonVariables::Inv_column_matrix[2][3], state[3][c]);
        temp[3][c] = AES::galoisMul(CommonVariables::Inv_column_matrix[3][0], state[0][c])
                   ^ AES::galoisMul(CommonVariables::Inv_column_matrix[3][1], state[1][c])
                   ^ AES::galoisMul(CommonVariables::Inv_column_matrix[3][2], state[2][c])
                   ^ AES::galoisMul(CommonVariables::Inv_column_matrix[3][3], state[3][c]);
    }
    memcpy(state, temp, 16);
}


void AES::Decrypt_first_round(uint8_t state[4][4], uint8_t cipher_key[4][4])
{

    InvAddRoundKey(state, cipher_key);

}

void AES::Decrypt_one_round(uint8_t state[4][4], uint8_t cipher_key[4][4])
{
    InvSubBytes(state);
    InvShiftRows(state);
    AddRoundKey(state,cipher_key);
    InvMixColumns(state);

 }

void AES::Decrypt(uint8_t input[16], cbyte key[], uint8_t output[4][4], AESMode mode) 
    {   

        cbyte state[4][4];

        AES::copyToState(input, state);

        int8_t numRounds = 0;
        numRounds = mode.Nr;

        word* expandedKey = initializeExpandedKey(mode.Nr);

        AES::lockExpandedKeyMemory(expandedKey, mode);

        AES::keyExpansion(key, expandedKey, mode);
        int8_t expandedKeyLength = (mode.Nr+1)*4;
 

        uint8_t roundKey [4][4]=
        {   {expandedKey[expandedKeyLength - 4][0], expandedKey[expandedKeyLength - 3][0], expandedKey[expandedKeyLength - 2][0], expandedKey[expandedKeyLength - 1][0]},
            {expandedKey[expandedKeyLength - 4][1], expandedKey[expandedKeyLength - 3][1], expandedKey[expandedKeyLength - 2][1], expandedKey[expandedKeyLength - 1][1]},
            {expandedKey[expandedKeyLength - 4][2], expandedKey[expandedKeyLength - 3][2], expandedKey[expandedKeyLength - 2][2], expandedKey[expandedKeyLength - 1][2]},
            {expandedKey[expandedKeyLength - 4][3], expandedKey[expandedKeyLength - 3][3], expandedKey[expandedKeyLength - 2][3], expandedKey[expandedKeyLength - 1][3]} };


        AES::AddRoundKey(state, roundKey);


        for (int8_t roundCounter = numRounds -1 ; roundCounter >= 0; roundCounter--)
        {
            for (uint8_t i = 0; i < 4; i++)
            {
                for (uint8_t j = 0; j < 4; j++)
                {
                    
                    roundKey[i][j] = expandedKey[roundCounter*4 + j][i];
                }
            }

            AES::InvShiftRows(state);
            AES::InvSubBytes(state);
            AES::AddRoundKey(state, roundKey);

            if (roundCounter != 0)
            {
                // Apply MixColumns in all rounds but the last
                AES::InvMixColumns(state);
            }
        }

        AES::unlockExpandedKeyMemory(expandedKey, mode);
        AES::clearExpandedKeyMem(expandedKey, mode);
        // Copying final state to output
        for (uint8_t i = 0; i < 4; i++)
        {
            for (uint8_t j = 0; j < 4; j++)
            {
                output[i][j] = state[i][j];
            }
        }
    }