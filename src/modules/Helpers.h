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

    void copyToState(cbyte input[16], cbyte state[4][4]);
    
}
#endif