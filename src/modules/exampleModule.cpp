// my_class.cpp
#include "exampleModule.h" // header in local directory
#include <iostream> // header in standard library

using namespace examples;
using namespace std;

void my_class::do_something()
{
    cout << "Doing something!" << endl;
}