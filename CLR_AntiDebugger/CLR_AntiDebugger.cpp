#include "pch.h"
#include "AntiDebugger.h"
using namespace System;

int main(array<System::String ^> ^args)
{
    auto antidebugger = antinet::AntiDebugger();
    std::cout << antidebugger.HasDebugger();
    return 0;
}
