#include "Helpers.h"
#include "CBC.h"
#include "RNG.h"
#include "encryptionModule.h"
#include "decryptionModule.h"
#include <iostream>
using namespace std;
using namespace AES;

AES::CBC::CBC(cbyte* key, AESMode mode)
{
    this->mode = mode;
    this->keyLen = 4*this->mode.Nk;
    this->key = new cbyte[this->keyLen];
    this->IVOverwritten = false;
    for (int i = 0; i<this->keyLen; i++)
    {
        this->key[i] = key[i];
    }
    
    lockMemory(this->key,this->keyLen);
    //here we followed practice MSC41-C. Never hard code sensitive information 
    //we stored our key in a secure memory 
}

AES::CBC::~CBC()
{
    clearMem<cbyte>(this->key, this->keyLen);
    unlockMemory(this->key, this->keyLen);
    delete [] this->key;
    this->key = NULL;

    if(this->paddedMessage)
    {
        unlockMemory(this->paddedMessage, this->paddedSize);
        clearMem<cbyte>(this->paddedMessage, this->paddedSize);
        delete [] this->paddedMessage;
        this->paddedMessage = NULL;
    }
    if(this->IV)
    {
        clearMem<cbyte>(this->IV, 16);
        delete [] this->IV;
        this->IV = NULL;
    }
}

void AES::CBC::pad(cbyte* message, int size)
{
    this->paddedSize = (size/16)*16 + 16;
    this->nBlocks = paddedSize/16;
    this->nPadding = this->paddedSize - size;

    this->paddedMessage = new cbyte[this->paddedSize];
    lockMemory(this->paddedMessage, this->paddedSize);

    int i = 0;
    while (i<size)
    {
        this->paddedMessage[i] = message[i];
        i++;
    }

    while (i<this->paddedSize)
    {
        this->paddedMessage[i] = this->nPadding;
        i++;
    }
    
}

void AES::CBC::createMessageBlocks()
{
    this->paddedMessageBlocks = new cbyte*[this->nBlocks];

    lockMemory(this->paddedMessageBlocks, this->nBlocks);

    int j = 0;
    for(int i = 0; i<nBlocks; i += 16)
    {
        this->paddedMessageBlocks[i] = new cbyte[16];
        AES::copyMem(this->paddedMessageBlocks[i], this->paddedMessage + j, 16);
        lockMemory(this->paddedMessageBlocks[i], 16);
    }

    unlockMemory(this->paddedMessage, this->paddedSize);
    clearMem<cbyte>(this->paddedMessage, this->paddedSize);
    delete [] this->paddedMessage;
    this->paddedMessage = NULL;
}


void AES::CBC::generateIV()
{
    this->IV = new cbyte[16];
    genCryptoRN(16, this->IV);   //here we randomly generate IV 
    //we followed practice MSC30-C. Do not use the rand() function for generating pseudorandom numbers 
    //we use a function from our implementation based on BCryptOpenAlgorithmProvider
}

void AES::CBC::overwriteIV(cbyte* IV)
{
    this->IV = new cbyte[16];
    AES::copyMem(this->IV, IV, 16);
    this->IVOverwritten = true;
}

void AES::CBC::PRF(cbyte* input, cbyte* output)
{
    cbyte state[4][4];
    Encrypt(input, this->key, state, this->mode);
    copyFromState(input, state);
}


void AES::CBC::PRFInv(cbyte* input, cbyte* output)
{
    cbyte state[4][4];
    Decrypt(input, this->key, state, this->mode);
    copyFromState(input, state);
}

cbyte* AES::CBC::encrypt(cbyte* message, int size, int& cipherSize)
{
    this->pad(message, size);
    cipherSize = this->paddedSize + 16;
    cout<<this->mode.Nk;
    if(!this->IVOverwritten)
    {
        this->generateIV();
    }

    cbyte* cipher = new cbyte[cipherSize];

    cbyte* c = this->IV;
    cbyte* m = this->paddedMessage;

    AES::copyMem(cipher, this->IV, 16);

    for (int j = 0; j<=this->paddedSize - 16; j += 16)
    {
        m = this->paddedMessage + j;
        cbyte* cipherBlock = cipher + j + 16;
        xorArrays(c, m, cipherBlock, 16);

        PRF(cipherBlock);

        c = cipherBlock;
        
    }

    cout<<cipherSize;

    unlockMemory(this->paddedMessage, this->paddedSize);
    clearMem<cbyte>(this->paddedMessage, this->paddedSize);
    delete [] this->paddedMessage;
    this->paddedMessage = NULL;

    clearMem<cbyte>(this->IV, 16);
    delete [] this->IV;
    this->IV = NULL;

    this->IVOverwritten = false;

    return cipher;

}


cbyte* AES::CBC::decrypt(cbyte* cipher, int size, int& messageSize)
{

    overwriteIV(cipher);
    this->paddedSize = size;

    this->paddedMessage = new cbyte[this->paddedSize];
    lockMemory(this->paddedMessage, this->paddedSize);

    cbyte* cPrev = this->IV;
    cbyte* m;

    for (int j = 0; j<=this->paddedSize - 16; j += 16)
    {
        m = this->paddedMessage + j;
        cbyte* cipherBlock = cipher + j + 16;

        copyMem(m,cipherBlock, 16);
        PRFInv(m);
        xorArrays(cPrev, m, m, 16);

        cPrev = cipherBlock;
    }


    clearMem<cbyte>(this->IV, 16);
    delete [] this->IV;
    this->IV = NULL;

    this->IVOverwritten = false;

    return this->paddedMessage;

}