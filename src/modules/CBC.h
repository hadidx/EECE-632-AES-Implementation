#ifndef CBC_H
#define CBC_H
#include "Helpers.h"
namespace AES{
    class CBC
    {
    private:
        cbyte* key;
        AESMode mode;
        int keyLen;
        cbyte* paddedMessage;
        cbyte** paddedMessageBlocks;
        int paddedSize;
        int nBlocks;
        int nPadding;
        bool IVOverwritten;
        void pad(cbyte* message, int size);
        void createMessageBlocks();
        int locatePadStart();
        void generateIV();
        void PRF(cbyte* input, cbyte* output=NULL);
        void PRFInv(cbyte* input, cbyte* output=NULL);
        cbyte* IV;
    public:
        CBC(cbyte* key, AESMode mode);
        ~CBC();
        cbyte* encrypt(cbyte* message, int size, int& cipherSize);
        void overwriteIV( cbyte* IV);
        cbyte* decrypt(cbyte* cipher, int size, int& messageSize);
    };
    
    
}


#endif