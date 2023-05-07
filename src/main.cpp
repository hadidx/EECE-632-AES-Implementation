#include <iostream>
#include "exampleModule.h"
#include "timing.h"
#include "Helpers.h"
#include "RNG.h"

using namespace AES;
using namespace std;
using namespace examples;
//execute actual program here

int main()
{
    AES::AESMode mode;
    mode = CommonVariables::AES128;
    uint8_t output[4][4];
    cbyte key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    // timeAES(key, mode, 13, 200*256, "timeAES.csv");
    timeGalios(200000*256, "timeGalois.csv");

}