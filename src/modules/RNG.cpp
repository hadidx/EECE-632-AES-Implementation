#include "Helpers.h"
#include "RNG.h"
using namespace AES;

#ifdef _WIN32 //windows implementation of the random number generator using BCryptGenRandom
#include <Windows.h>
#include <bcrypt.h>
unsigned int AES::genCryptoRN(int n, cbyte* rn) //n is number of bytes and rn stores the generated output
{
    NTSTATUS s;

    BCRYPT_ALG_HANDLE handle;
    BCryptOpenAlgorithmProvider( &handle,BCRYPT_RNG_ALGORITHM,NULL,0);

    s = BCryptGenRandom(handle, rn, n, 0);
    if (s != 0) //return 1 or 0 to indicate the success or failure of the generation.
        return 1;
    return 0;
}
#else// Unix implementation of the random number generator using the urandom device
#include <iostream>
#include <fstream>
using namespace std;
unsigned int AES::genCryptoRN(int n, cbyte* rn)
{ 
    ifstream random("/dev/urandom", ios::in|ios::binary);
    if(random) // return 1 or 0 to indicate the success or failure of the generation
    {
        random.read(reinterpret_cast<char*>(rn), n); 
        if(random)
        {
            random.close(); 
            return 1;
        }
        else 
        {
            random.close(); 
            return 0;
        }
        
    }
    else 
    {
        return 0;
    }
    return 1;
}
#endif
