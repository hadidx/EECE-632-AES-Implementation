#include <iostream>

#include "simpletest.h"

using namespace std;

//write tests in this file or in a different file and include them as per the simpletest documentation
//compile this file and link dependancies to run all tests

DEFINE_TEST(SimpleTestExample)
{
    TEST(1==true); //silly example that succeeds because 1 is equal to true
}

int main()
{
    bool pass = true;
    pass &= TestFixture::ExecuteTestGroup("Global", TestFixture::Verbose); //execute all tests
    return pass ? 0 : 1;
}