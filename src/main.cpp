#include <iostream>
#include "exampleModule.h"
#include "Helpers.h"
#include "RNG.h"

using namespace AES;
using namespace std;
using namespace examples;
//execute actual program here

int main()
{
    cbyte rn[16];
    genCryptoRN(16, rn);
    for(int i = 0; i < 16; i++)
    {
        cout<<(int)(rn[i])<<" ";
    }
}