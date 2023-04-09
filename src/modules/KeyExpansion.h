#ifndef KEYEXPANSION_H
#define KEYEXPANSION_H

#include <stdint.h>
#include "Helpers.h"
namespace AES
{
    void RotWord(word w);

    void SubWord(word w);

    void xorRcon(word w, cbyte i);

    word initiallizeWord(cbyte a0, cbyte a1, cbyte a2, cbyte a3);

    word xorWords(word w1, word w2);

    word* initializeExpandedKey(int Nr);

    void lockExpandedKeyMemory(word* expandedKey, AESMode mode);

    void unlockExpandedKeyMemory(word* expandedKey, AESMode mode);

    void clearExpandedKeyMem(word* expandedKey, AESMode mode);

    void keyExpansion (cbyte* key, word* expandedKey, AESMode mode);

}
#endif