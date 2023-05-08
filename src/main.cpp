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
    // timeSbox(13, 200000*256, "timeAES.csv");
    timeGalios(200000*256, "timeGalois.csv");

}