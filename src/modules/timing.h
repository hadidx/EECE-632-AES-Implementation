#ifndef TIMING_H
#define TIMING_H

#include <stdint.h>
#include "Helpers.h"
#include <cstring>

namespace AES{
    uint64_t rdtsc();

    void timeSbox(int targetByte, long long nTotalSamples, string outputFileName);

    void timeGalios(long long nTotalSamples, string outputFileName);
}

#endif