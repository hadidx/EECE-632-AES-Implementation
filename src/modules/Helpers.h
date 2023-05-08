#ifndef HELPERS_H
#define HELPERS_H

#include <stdint.h>
#include <iostream>
using namespace std;
namespace AES
{
    typedef uint8_t cbyte;
    typedef uint8_t* word;
    #define declareWord(var) cbyte* var = new cbyte[4];
    #define printHex(var) cout<<hex<<var<<dec;

    struct AESMode
    {
        AESMode(int Nk, int Nr);
        AESMode();
        AESMode& operator = (const AESMode& mode);
        int Nk;
        int Nr;
    };
    
    struct CommonVariables
    {
        const static cbyte S_BOX[256];
        const static cbyte Inv_S_BOX[256];
        const static cbyte column_matrix[4][4];
        const static cbyte Inv_column_matrix[4][4];
        const static cbyte RCON[10];
        const static AESMode AES128;
        const static AESMode AES192;
        const static AESMode AES256;
    };
    
    uint8_t galoisMulBranched(uint8_t a, uint8_t b);

    uint8_t galoisMul(uint8_t a, uint8_t b);

    uint8_t galoisMulMirror(uint8_t a, uint8_t b);

    void copyToState(cbyte input[16], cbyte state[4][4]);

    void copyFromState(cbyte output[16], cbyte state[4][4]);

    bool lockMemory(void* ptr, int size);

    bool unlockMemory(void* ptr, int size);


    void copyMem(cbyte* dest, cbyte* src, int size);

    template <typename T> void clearMem(T* ptr, int size)
    {
        for (int i = 0; i< size; i++)
        {
            *(ptr + i) = 0x00;
        }
    }

    void xorArrays(cbyte* a, cbyte* b, cbyte* output, int size);

    cbyte sBoxLookup(int i); //bad do not use

    cbyte sBoxInvLookup(int i); 

    cbyte sBoxPeicewiseExpression(int i);

    cbyte sBoxInvPeicewiseExpression(int i);

    cbyte sBoxPeicewiseLoop(int i);

    cbyte sBoxInvPeicewiseLoop(int i);

    cbyte sBoxInverseAndAffinity(int i);
    
    cbyte inverse(cbyte a);

    cbyte xorAllbits(cbyte a);

    cbyte leftRotate(cbyte n, unsigned int d);


}
#endif