#include <iostream>

#include "simpletest.h"

using namespace std;

//write tests in this file or in a different file inside the ./tests directory
//compile this file and link dependancies to run all tests

int main()
{
    bool pass = true;
    pass &= TestFixture::ExecuteTestGroup("Global", TestFixture::Verbose); //execute all tests
    return pass ? 0 : 1;
}