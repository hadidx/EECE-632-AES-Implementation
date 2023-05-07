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


void timedFunction(uint8_t input[16])
{
    for(int i = 0; i<16; i++)
    {
        AES::sBoxInverseAndAffinity(input[i]);
    }
}

void AES::timeAES(cbyte key[16], AESMode mode, int targetByte, long long nTotalSamples, string outputFileName)
{
    // uint8_t output[4][4];
    // lockMemory(output,16);
    // lockMemory(key,16);
    long long nSamplesPerTargetByteValue = nTotalSamples/256;

    // uint64_t* times = new uint64_t[nSamplesPerTargetByteValue];

    double averageTimesPerByte[256];
    double counts[256];  

    for (int i = 0; i<256; i++)
    {
        averageTimesPerByte[i] = 0;
    }

    for (int i = 0; i<256; i++)
    {
        counts[i] = 1;
    }

    std::random_device engine;
    
    for (long long i = 0; i<256; ++i)
    {

        // uint8_t** inputs = new uint8_t*[nSamplesPerTargetByteValue];
        // for(long long j = 0; j<nSamplesPerTargetByteValue; j++)
        // {
        //     uint8_t* input = new uint8_t[16];
        //     for (long long k = 0; k<16; ++k)
        //     {
        //         input[k] = engine();
        //     }

        //     // input[targetByte] = engine();
        // }

        for (long long j = 0; j<nSamplesPerTargetByteValue; ++j)
        {   

            uint8_t* input = new uint8_t[16];
            for (long long k = 0; k<16; ++k)
            {
                input[k] = engine();
            }
            // for (long long k = 0; k<16; ++k)
            // {
            //     inputs[j][k];
            // }
            auto begin = chrono::high_resolution_clock::now();
                timedFunction(input);
            auto end = chrono::high_resolution_clock::now();
            averageTimesPerByte[input[targetByte]] += chrono::duration_cast<chrono::nanoseconds>(end - begin).count();
            counts[input[targetByte]] += 1;
            delete input;
        }

        // for(long long j = 0; j<nSamplesPerTargetByteValue; j++)
        // {
        //     delete [] inputs[j];
        // }

        // delete [] inputs;
    }

    for (long long i = 0; i<256; ++i)
    {
        averageTimesPerByte[i] = averageTimesPerByte[i]/counts[i];
    }


    ofstream myfile (outputFileName);

    for (long i = 0; i<256; ++i)
    {
        myfile << averageTimesPerByte[i] << "," ;
    }

     myfile.close();

    
}

void AES::timeGalios(long long nTotalSamples, string outputFileName)
{
    double averageTimesPerByte[256];
    double counts[256];  

    for (int i = 0; i<256; i++)
    {
        averageTimesPerByte[i] = 0;
    }

    for (int i = 0; i<256; i++)
    {
        counts[i] = 1;
    }

    std::random_device engine;


    for (long long j = 0; j<nTotalSamples; ++j)
    {   

        uint8_t input1 = engine();
        uint8_t input2 = engine();
    
        auto begin = chrono::high_resolution_clock::now();
            galoisMulBranched(input1,input2);
        auto end = chrono::high_resolution_clock::now();
        averageTimesPerByte[input1] += chrono::duration_cast<chrono::nanoseconds>(end - begin).count();
        counts[input1] += 1;
    }

    for (long long i = 0; i<256; ++i)
    {
        averageTimesPerByte[i] = averageTimesPerByte[i]/counts[i];
    }

    

    ofstream myfile (outputFileName);

    for (long i = 0; i<256; ++i)
    {
        myfile << averageTimesPerByte[i] << "," ;
    }

     myfile.close();

}
