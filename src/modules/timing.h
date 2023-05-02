#ifndef TIMING_H
#define TIMING_H

#include <stdint.h>
#include "Helpers.h"
#include <cstring>

namespace AES{
    uint64_t rdtsc();

    void timeAES(cbyte key[16], AESMode mode, int targetByte, int nTotalSamples, string outputFileName);
}

#endif