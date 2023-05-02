#include "timing.h"
#include "encryptionModule.h"
#include <random> //sufficient for generating random input for timing purpuses.
#include <chrono>
#include <fstream>
using namespace AES;

//  Windows
#ifdef _WIN32

#include <intrin.h>
uint64_t AES::rdtsc(){
    return __rdtsc();
}

//  Linux/GCC
#else
#include <x86intrin.h>
uint64_t AES::rdtsc(){
    unsigned int lo,hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}
#endif


void AES::timeAES(cbyte key[16], AESMode mode, int targetByte, int nTotalSamples, string outputFileName)
{
    uint8_t output[4][4];
    lockMemory(output,16);
    lockMemory(key,16);
    int nSamplesPerTargetByteValue = nTotalSamples/256;

    uint64_t* times = new uint64_t[256*nSamplesPerTargetByteValue];

    double averageTimesPerByte[256]; 

    uint8_t** inputs = new uint8_t*[256*nSamplesPerTargetByteValue];

    std::random_device engine;

    for (int i = 0; i<256; ++i)
    {
        for (int j = 0; j<nSamplesPerTargetByteValue; ++j)
        {
            uint8_t* input = new uint8_t[16];
            for (int k = 0; k<16; ++k)
            {
                input[k] = engine();
            }

            input[targetByte] = i;
            lockMemory(input,16);
            inputs[i*nSamplesPerTargetByteValue+j] = input;
        }
    }

    
    
    for (int i = 0; i<256*nSamplesPerTargetByteValue; ++i)
    {
        uint8_t input[16]; 
        for (int j=0; j<16; j++)
        {
            input[j] = inputs[i][j];
        }
        lockMemory(input,16);
        auto begin = rdtsc();
        Encrypt(input, key, output, mode);
        auto end = rdtsc();
        unlockMemory(input,16);

        times[i] = (double)(end-begin);
    }


    for (int i = 0; i<256; ++i)
    {
        for (int j = 0; j<nSamplesPerTargetByteValue; ++j)
        {
            averageTimesPerByte[i] += times[i*nSamplesPerTargetByteValue+j];
        }


        averageTimesPerByte[i] = averageTimesPerByte[i]/(double)nSamplesPerTargetByteValue;
    }


    ofstream myfile (outputFileName);

    unlockMemory(output,16);
    unlockMemory(key,16);
    if (myfile.is_open())
    {
        for(int i = 0; i<256; i ++){
            myfile << averageTimesPerByte[i] << "," ;
        }
        myfile.close();
    }

    for (int i = 0; i<256*nSamplesPerTargetByteValue; ++i)
    {
        unlockMemory(inputs[i],16);
        delete [] inputs[i];
    }

    delete [] inputs;
    delete times;
    
}