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
        static cbyte S_BOX[256];
        static cbyte column_matrix[4][4];
        static cbyte RCON[10];
        static AESMode AES128;
        static AESMode AES192;
        static AESMode AES256;
    };
    
}
#endif