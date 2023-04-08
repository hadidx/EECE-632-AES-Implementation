#include "Helpers.h"
#include "RNG.h"
using namespace AES;

#ifdef _WIN32
#include <Windows.h>
#include <bcrypt.h>
unsigned int AES::genCryptoRN(int n, cbyte* rn)
{
    NTSTATUS s;

    BCRYPT_ALG_HANDLE handle;
    BCryptOpenAlgorithmProvider( &handle,BCRYPT_RNG_ALGORITHM,NULL,0);

    s = BCryptGenRandom(handle, rn, n, 0);
    if (s != 0)
        return 1;
    return 0;
}
#else
#include <iostream>
#include <fstream>
using namespace std;
unsigned int AES::genCryptoRN(int n, cbyte* rn)
{ 
    ifstream random("/dev/urandom", ios::in|ios::binary);
    if(random) 
    {
        random.read(reinterpret_cast<char*>(rn), n); 
        if(random)
        {
            return 0;
        }
        else 
        {
            return 1;
        }
        random.close(); 
    }
    else 
    {
        return 1;
    }
    return 0;
}
#endif
