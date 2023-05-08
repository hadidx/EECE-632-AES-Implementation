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
    
    this->keyLocked = lockMemory(this->key,this->keyLen);
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

//Pad the message
void AES::CBC::pad(cbyte* message, int size)
{
    //padding can add an extra block if message length is multiple of 16 bytes
    this->paddedSize = (size/16)*16 + 16;
    this->nBlocks = paddedSize/16;
    this->nPadding = this->paddedSize - size;

    try{ //handle memory allocation failure
        this->paddedMessage = new cbyte[this->paddedSize];
    }
    catch(...)
    {
        this->paddedMessage = NULL;
    }
    
    this->paddedMessageLocked = lockMemory(this->paddedMessage, this->paddedSize);

    if( this->paddedMessage != NULL && !this->paddedMessageLocked)
    {
        //clear memory
        clearMem<cbyte>(this->paddedMessage, this->paddedSize);
        delete [] this->paddedMessage;
    }

    //don't access padded message unless it is locked and allocated
    if(this->paddedMessageLocked&&this->paddedMessage != NULL)
    {
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
    
}

// void AES::CBC::createMessageBlocks()
// {
//     this->paddedMessageBlocks = new cbyte*[this->nBlocks];

//     lockMemory(this->paddedMessageBlocks, this->nBlocks);

//     int j = 0;
//     for(int i = 0; i<nBlocks; i += 16)
//     {
//         this->paddedMessageBlocks[i] = new cbyte[16];
//         AES::copyMem(this->paddedMessageBlocks[i], this->paddedMessage + j, 16);
//         lockMemory(this->paddedMessageBlocks[i], 16);
//     }

//     unlockMemory(this->paddedMessage, this->paddedSize);
//     clearMem<cbyte>(this->paddedMessage, this->paddedSize);
//     delete [] this->paddedMessage;
//     this->paddedMessage = NULL;
// }

//generate the IV and handle exceptions
unsigned int AES::CBC::generateIV()
{
    try{ //handle memory allocation failure
        this->IV = new cbyte[16];
    }
    catch(...){
        return 0;
    }
    return genCryptoRN(16, this->IV);
}

//Can be used to use a custom IV (For MAC implementations)
void AES::CBC::overwriteIV(cbyte* IV)
{
    this->IV = new cbyte[16];
    AES::copyMem(this->IV, IV, 16);
    this->IVOverwritten = true;
}

//Use AES as PRF
void AES::CBC::PRF(cbyte* input, cbyte* output)
{
    cbyte state[4][4];
    Encrypt(input, this->key, state, this->mode);
    copyFromState(input, state);
}

//Use AES Decrypt as PRF^-1
void AES::CBC::PRFInv(cbyte* input, cbyte* output)
{
    cbyte state[4][4];
    Decrypt(input, this->key, state, this->mode);
    copyFromState(input, state);
}

cbyte* AES::CBC::encrypt(cbyte* message, int size, int& cipherSize)
{
    this->pad(message, size); //pad message and lock memory
    cipherSize = this->paddedSize + 16;
    cout<<this->mode.Nk;

    bool validIV = true;
    if(!this->IVOverwritten)
    {
        validIV = this->generateIV();
    }

    //do not encrypt if Iv not valid or memory not locked
    //then free resources
    if (!validIV||!this->paddedMessageLocked||!this->keyLocked)
    {
         //unlock and clear memory
        unlockMemory(this->paddedMessage, this->paddedSize);
        clearMem<cbyte>(this->paddedMessage, this->paddedSize);
        delete [] this->paddedMessage;
        this->paddedMessage = NULL;

        clearMem<cbyte>(this->IV, 16);
        delete [] this->IV;
        this->IV = NULL;

        this->IVOverwritten = false;
    
        return NULL;
    }

    //do not encrypt if memory not allocated
    //then free resources
    if(this->paddedMessage==NULL)
    {
        //clear memory
        clearMem<cbyte>(this->IV, 16);
        delete [] this->IV;
        this->IV = NULL;

        this->IVOverwritten = false;
    
        return NULL;
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

    //unlock and clear memory
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

    try{//handle memory allocation failure

        this->paddedMessage = new cbyte[this->paddedSize];
    }
    catch(...)
    {
        this->paddedMessage = NULL;
    }
    this->paddedMessageLocked = lockMemory(this->paddedMessage, this->paddedSize);

    //only decrypt if memory locked and memory allocated
    //then free resources
    if (!this->paddedMessageLocked||!this->keyLocked||this->paddedMessage==NULL)
    {
        //unlock and clear memory
        unlockMemory(this->paddedMessage, this->paddedSize);
        clearMem<cbyte>(this->paddedMessage, this->paddedSize);
        delete [] this->paddedMessage;
        this->paddedMessage = NULL;

        clearMem<cbyte>(this->IV, 16);
        delete [] this->IV;
        this->IV = NULL;

        this->IVOverwritten = false;
    
        return NULL;
    }
    
    //don't decrypt if the memory is not allocated
    //then free resources
    if(this->paddedMessage==NULL)
    {
        //clear memory
        clearMem<cbyte>(this->IV, 16);
        delete [] this->IV;
        this->IV = NULL;

        this->IVOverwritten = false;
    
        return NULL;
    }

    cbyte* cPrev = this->IV;
    cbyte* m;

    //Perform the CBC operations
    for (int j = 0; j<=this->paddedSize - 16; j += 16)
    {
        m = this->paddedMessage + j;
        cbyte* cipherBlock = cipher + j + 16;

        copyMem(m,cipherBlock, 16);
        PRFInv(m);
        xorArrays(cPrev, m, m, 16);

        cPrev = cipherBlock;
    }

    //clear the memory when the decryotion is done
    clearMem<cbyte>(this->IV, 16);
    delete [] this->IV;
    this->IV = NULL;

    this->IVOverwritten = false;

    return this->paddedMessage;

}