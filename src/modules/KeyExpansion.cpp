#include "KeyExpansion.h"
#include <stdint.h>
#include "Helpers.h"

using namespace AES;

void AES::RotWord(word w)
{
    cbyte w0 = w[0];
    cbyte w1 = w[1];
    cbyte w2 = w[2];
    cbyte w3 = w[3];

    w[0] = w1;
    w[1] = w2;
    w[2] = w3;
    w[3] = w0;
}

void AES::SubWord(word w)
{
    w[0] = CommonVariables::S_BOX[w[0]];
    w[1] = CommonVariables::S_BOX[w[1]];
    w[2] = CommonVariables::S_BOX[w[2]];
    w[3] = CommonVariables::S_BOX[w[3]];
}

void AES::xorRcon(word w, cbyte i)
{
    w[0] = w[0]^CommonVariables::RCON[i-1];
}

word AES::xorWords(word w1, word w2)
{
    return initiallizeWord(w1[0]^w2[0],w1[1]^w2[1] ,w1[2]^w2[2] ,w1[3]^w2[3]);
}

word* AES::initializeExpandedKey(int Nr)
{
    word* expandedKey = new word[4*(Nr + 1)];

    return expandedKey;
}


void AES::lockExpandedKeyMemory(word* expandedKey, AESMode mode)
{
    lockMemory(expandedKey, 4*(mode.Nr + 1));
    for (int i = 0; i<4*(mode.Nr + 1); i++)
    {
        lockMemory(expandedKey[i], 4);
    }
}

void AES::unlockExpandedKeyMemory(word* expandedKey, AESMode mode)
{
    unlockMemory(expandedKey, 4*(mode.Nr + 1));
    for (int i = 0; i<4*(mode.Nr + 1); i++)
    {
        unlockMemory(expandedKey[i], 4);
    }
}


void AES::clearExpandedKeyMem(word* expandedKey, AESMode mode)
{
    for (int i = 0; i<4*(mode.Nr + 1); i++)
    {
        clearMem(expandedKey[i], 4);
        delete [] expandedKey[i];
        expandedKey[i] = NULL;
    }
    clearMem(expandedKey, 4*(mode.Nr + 1));
    delete [] expandedKey;
    expandedKey = NULL;
}

word AES::initiallizeWord(cbyte a0, cbyte a1, cbyte a2, cbyte a3)
{
    declareWord(w);
    w[0] = a0;
    w[1] = a1;
    w[2] = a2;
    w[3] = a3;

    return w;
}


void AES::keyExpansion (cbyte* key, word* expandedKey, AESMode mode)
{
    int i = 0;

    while(i < mode.Nk)
    {
        expandedKey[i] = initiallizeWord(key[4*i], key[4*i + 1], key[4*i + 2], key[4*i + 3]);
        i++;
    }

    i = mode.Nk;

    while (i < 4 * (mode.Nr + 1))
    {
        word previousWord = expandedKey[i - 1];
        word temp = initiallizeWord(previousWord[0], previousWord[1], previousWord[2], previousWord[3]);
        if(i % mode.Nk == 0)  //here we followed the practice EXP45-C. Do not perform assignments in selection statements 
        {
            RotWord(temp);
            SubWord(temp);
            xorRcon(temp, i/mode.Nk);
        }
        else if(mode.Nk > 6 && i % mode.Nk == 4) //also here we followed the practice EXP45-C. Do not perform assignments in selection statements 
        {
            SubWord(temp);
        }

        expandedKey[i] = xorWords(expandedKey[i - mode.Nk], temp);

        i++;
    }
}