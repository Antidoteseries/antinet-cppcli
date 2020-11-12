/*
 * antinet with C++/CLI 
 * by Antidotes (https://github.com/Antidoteseries)
 * 
 * Thanks to the original C# code:
 * https://github.com/wwh1004/antinet
 * https://github.com/0xd4d/antinet
 */

#include "AntiDebugger.h"
#include "AntiManagedDebugger.h"
#include "DynamicCRC32.h"
#include "ldasm.h"

using namespace System;
using namespace System::Diagnostics;
using namespace System::IO;
using namespace System::Reflection;
using namespace System::Runtime::InteropServices;
using namespace System::Text;
using namespace std;

namespace antinet {
    auto Crc32 = DynamicCrc32();
    bool AntiDebugger::PreventManagedDebugger()
    {
        if (_isManagedDebuggerPrevented)
            return true;
        _isManagedDebuggerPrevented = AntiManagedDebugger::Initialize();
        return _isManagedDebuggerPrevented;
    }

    // Detect anytype of debugger
    bool AntiDebugger::HasDebugger()
    {
        return HasUnmanagedDebugger() || HasManagedDebugger();
    }

    // Detect unmanaged debugger
    bool AntiDebugger::HasUnmanagedDebugger()
    {
        bool isDebugged;

        if (IsDebuggerPresent())
            return true;

        if (!CheckRemoteDebuggerPresent(GetCurrentProcess(), (PBOOL)(&isDebugged)))
            return true;

        if (isDebugged)
            return true;

        try {
            CloseHandle((HANDLE)0xDEADC0DE);
        }
        catch (...) {
            return true;
        }
        return false;
    }

    // Chck managed debugger
    // It can not detect unmanaged debugger (IDA Pro, OllyDbg, x64dbg, etc.)
    bool AntiDebugger::HasManagedDebugger()
    {
        byte *opcodes;
        byte *pCodeStart;
        byte *pCodeCurrent;
        byte *pCodeEnd;
        ldasm_data ldasmData;
        bool is64Bit;

        InitializeManaged();

        // Using clr!DebugDebugger::IsDebuggerAttached() to detect managed debugger
        if (_isDebuggerAttached())
            return true;
        // Can not insure threr isn't debugger 

        if (_pIsDebuggerAttached[0] == 0x33 && _pIsDebuggerAttached[1] == 0xC0 && _pIsDebuggerAttached[2] == 0xC3)
            return true; // The specific for dnSpy (anti-antidebugger)


        opcodes = new byte[_isDebuggerAttachedLength];
        pCodeStart = _pIsDebuggerAttached;
        pCodeCurrent = pCodeStart;
        pCodeEnd = _pIsDebuggerAttached + _isDebuggerAttachedLength;
        is64Bit = sizeof(void *) == 8;

        // Copy Opcodes
        while (true) {
            unsigned int length;

            length = Ldasm::ldasm(pCodeCurrent, &ldasmData, is64Bit);
            if ((ldasmData.flags & Ldasm::F_INVALID) != 0)
                throw gcnew NotSupportedException();
            CopyOpcode(&ldasmData, pCodeCurrent, opcodes, (unsigned int)(pCodeCurrent - pCodeStart));
            pCodeCurrent += length;
            if (pCodeCurrent == pCodeEnd)
                break;
        }

        // Check Opcodes CRC32
        if (Crc32.Compute(opcodes, _isDebuggerAttachedLength) != _isDebuggerAttachedCrc32)
            return true;
        return false;
    }

    bool AntiDebugger::_isDebuggerAttached()
    {
        bool (*fun)() = (bool (*)())(void *)_pIsDebuggerAttached;
        return fun();
    }

    void AntiDebugger::InitializeManaged()
    {
        HMODULE clrModuleHandle;
        LPWSTR lpFilename = new wchar_t[MAX_PATH];
        byte *clrFile;

        if (_isManagedInitialized)
            return;


        // Get IsDebuggerAttached function pointer 
        switch (Environment::Version->Major) {
        case 2:
            // Difference with .NET 4, Debugger.IsAttached.get invoke IsDebuggerAttached()
            _pIsDebuggerAttached = (byte *)(void *)(Debugger::typeid->GetMethod("IsDebuggerAttached", BindingFlags::NonPublic | BindingFlags::Static))->MethodHandle.GetFunctionPointer();
            clrModuleHandle = GetModuleHandleW(L"mscorwks.dll");
            break;
        case 4:
            // Debugger.IsAttached.get have [MethodImpl(MethodImplOptions.InternalCall)], it's direct pointer to CLR inner-function
            // Debugger.get_IsAttached() actually is clr!DebugDebugger::IsDebuggerAttached()
            _pIsDebuggerAttached = (byte *)(void *)(Debugger::typeid->GetMethod("get_IsAttached"))->MethodHandle.GetFunctionPointer();
            clrModuleHandle = GetModuleHandleW(L"clr.dll");
            break;
        default:
            throw gcnew NotSupportedException();
        }

        if (clrModuleHandle == nullptr)
            throw gcnew InvalidOperationException();

        if (!GetModuleFileNameW(clrModuleHandle, lpFilename, MAX_PATH))
            throw gcnew InvalidOperationException();

        // Get CLR file content 
        HANDLE clrFileHandle = CreateFileW(lpFilename, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        unsigned int clrFileSize = GetFileSize(clrFileHandle, nullptr);
        clrFile = new byte[clrFileSize];
        ReadFile(clrFileHandle, clrFile, clrFileSize, nullptr, nullptr);
        CloseHandle(clrFileHandle);

        byte *pPEImage = clrFile;

        unsigned int isDebuggerAttachedRva;
        unsigned int isDebuggerAttachedFoa;
        byte *pCodeStart;
        byte *pCodeCurrent;
        ldasm_data ldasmData;
        bool is64Bit;
        byte *opcodes;

        PEInfo peInfo(pPEImage);
        isDebuggerAttachedRva = (unsigned int)(_pIsDebuggerAttached - (byte *)clrModuleHandle);
        isDebuggerAttachedFoa = peInfo.ToFOA(isDebuggerAttachedRva);
        pCodeStart = pPEImage + isDebuggerAttachedFoa;
        pCodeCurrent = pCodeStart;
        is64Bit = sizeof(void *) == 8;

        // Allocate memory
        opcodes = new byte[0x200];

        // Copy Opcode till the first ret code find
        while (true) {
            unsigned int length = Ldasm::ldasm(pCodeCurrent, &ldasmData, is64Bit);

            if ((ldasmData.flags & Ldasm::F_INVALID) != 0)
                throw gcnew NotSupportedException();
            CopyOpcode(&ldasmData, pCodeCurrent, opcodes, (unsigned int)(pCodeCurrent - pCodeStart));
            if (*pCodeCurrent == 0xC3) {
                // found ret
                pCodeCurrent += length;
                break;
            }
            pCodeCurrent += length;
        }

        _isDebuggerAttachedLength = (unsigned int)(pCodeCurrent - pCodeStart);
        byte *pOpcodes = opcodes;
        _isDebuggerAttachedCrc32 = Crc32.Compute(pOpcodes, _isDebuggerAttachedLength);

        _isManagedInitialized = true;
    }

    void AntiDebugger::CopyOpcode(ldasm_data *pLdasmData, void *pCode, byte *opcodes, unsigned int offset) {
        for (byte i = 0; i < pLdasmData->opcd_size; i++)
            opcodes[offset + pLdasmData->opcd_offset + i] = ((byte *)pCode)[pLdasmData->opcd_offset + i];
    }

    AntiDebugger::PEInfo::PEInfo(byte *pPEImage) {
        byte *p;
        unsigned short optionalHeaderSize;

        _pPEImage = pPEImage;
        p = pPEImage;

        // NtHeader
        p += *(unsigned int *)(p + 0x3C);
        // Skip Signature + Machine
        p += 4 + 2;
        _sectionsCount = *(unsigned short *)p;
        // Skip NumberOfSections + TimeDateStamp + PointerToSymbolTable + NumberOfSymbols
        p += 2 + 4 + 4 + 4;
        optionalHeaderSize = *(unsigned short *)p;
        // Skip SizeOfOptionalHeader + Characteristics
        p += 2 + 2;
        // Skip OptionalHeader
        p += optionalHeaderSize;

        _pSectionHeaders = (IMAGE_SECTION_HEADER *)p;
    }

    unsigned int AntiDebugger::PEInfo::ToFOA(unsigned int rva) {
        for (unsigned int i = 0; i < _sectionsCount; i++)
            if (rva >= _pSectionHeaders[i].VirtualAddress && rva < _pSectionHeaders[i].VirtualAddress + max(_pSectionHeaders[i].Misc.VirtualSize, _pSectionHeaders[i].SizeOfRawData))
                return rva - _pSectionHeaders[i].VirtualAddress + _pSectionHeaders[i].PointerToRawData;
        return rva;
    }
}
