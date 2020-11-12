/*
 * Anti managed debugger code. Written by de4dot@gmail.com
 * This code is in the public domain.
 * Official site: https://github.com/0xd4d/antinet
 */

#include "AntiManagedDebugger.h"

using namespace System;
using namespace System::Runtime::ExceptionServices;
using namespace System::Runtime::InteropServices;
using namespace System::Security;
using namespace System::Text;

namespace antinet {
    // This class will make sure that no managed .NET debugger can attach and
    // debug this .NET process. This code assumes that it's Microsoft's .NET
    // implementation (for the desktop) that is used. The only currently supported
    // versions are .NET Framework 2.0 - 4.5 (CLR 2.0 and CLR 4.0).
    // It prevents debugging by killing the .NET debugger thread. When it's killed,
    // any attached managed debugger, or any managed debugger that attaches, will
    // fail to send and receive any .NET debug messages. If a debugger is attached,
    // <c>Debugger.IsAttached</c> will still return <c>true</c> but that doesn't mean
    // the debugger is working. It's just that the debugger flag isn't reset by our code.
    // If a debugger is attached before this code is executed, the process could hang at
    // some later time when this process is trying to send a debug message to the debugger.
    // Clearing the debug flag could possibly solve this if you don't want it to hang.

    // Must be called to initialize anti-managed debugger code
    bool AntiManagedDebugger::Initialize() {

        Info_CLR info = Getinfo();
        void *pDebuggerRCThread = FindDebuggerRCThreadAddress(info);
        if (pDebuggerRCThread == nullptr)
            return false;

        // This isn't needed but it will at least stop debuggers from attaching.
        // Even if they did attach, they wouldn't get any messages since the debugger
        // thread has exited. A user who tries to attach will be greeted with an
        // "unable to attach due to different versions etc" message. This will not stop
        // already attached debuggers. Killing the debugger thread will.

        byte *pDebuggerIPCControlBlock = (byte *)*(void **)((byte *)pDebuggerRCThread + info.DebuggerRCThread_pDebuggerIPCControlBlock);
        if (Environment::Version->Major == 2)
            // At CLR 2.0, it's a pointer to array (DebuggerIPCControlBlock**), but CLR 4.0+ is ebuggerIPCControlBlock*
            pDebuggerIPCControlBlock = (byte *)*(void **)pDebuggerIPCControlBlock;

        // Set size field to 0.
        // mscordbi!CordbProcess::VerifyControlBlock() will fail when it detects an unknown size.
        *(unsigned int *)pDebuggerIPCControlBlock = 0;

        // Signal debugger thread to exit
        *((byte *)pDebuggerRCThread + info.DebuggerRCThread_shouldKeepLooping) = 0;
        HANDLE hEvent = *(void **)((byte *)pDebuggerRCThread + info.DebuggerRCThread_hEvent1);
        SetEvent(hEvent);

        return true;
    }

    Info_CLR AntiManagedDebugger::Getinfo()
    {
        switch (Environment::Version->Major) {
        case 2:
            if (sizeof(void *) == 4)
            {
                // CLR 2.0 x86 offsets
                return Info_CLR(0x4, 0x8, 0x30, 0x34, 0x3C, 0x40);
            }
            else
            {
                // CLR 2.0 x64 offsets
                return Info_CLR(0x8, 0x10, 0x58, 0x60, 0x70, 0x78);
            }
        default:
        case 4:
            if (Environment::Version->Revision <= 17020)
            {
                if (sizeof(void *) == 4)
                {
                    // CLR 4.0 x86 offsets
                    return Info_CLR(0x8, 0xC, 0x34, 0x38, 0x40, 0x44);
                }
                else
                {
                    // CLR 4.0 x64 offsets
                    return Info_CLR(0x10, 0x18, 0x58, 0x60, 0x70, 0x78);
                }
            }
            else
            {
                if (sizeof(void *) == 4)
                {
                    // CLR 4.5 x86 offsets
                    return Info_CLR(0x8, 0xC, 0x30, 0x34, 0x3C, 0x40);
                }
                else
                {
                    //CLR 4.5 x64 offsets (this is the same in all CLR 4.0 versions)
                    return Info_CLR(0x10, 0x18, 0x58, 0x60, 0x70, 0x78);
                }
            }
        }
    }


    //[HandleProcessCorruptedStateExceptions, SecurityCritical]   // Req'd on .NET 4.0
    // Tries to find the address of the DebuggerRCThread instance in memory
    void *AntiManagedDebugger::FindDebuggerRCThreadAddress(Info_CLR info) {
        unsigned int pid = GetCurrentProcessId();

        try {
            PEInfo *peInfo = PEInfo::GetCLR();
            if (peInfo == nullptr)
                return nullptr;

            void *sectionAddr;
            unsigned int sectionSize;
            if (!peInfo->FindSection(".data", sectionAddr, sectionSize))
                return nullptr;

            // Try to find the Debugger instance location in the data section
            byte *p = (byte *)sectionAddr;
            byte *end = (byte *)sectionAddr + sectionSize;
            for (; p + sizeof(void *) <= end; p += sizeof(void *)) {
                void *pDebugger = *(void **)p;
                if (pDebugger == nullptr)
                    continue;

                try {
                    // All allocations are pointer-size aligned
                    if (!PEInfo::IsAlignedPointer(pDebugger))
                        continue;

                    // Make sure pid is correct
                    unsigned int pid2 = *(unsigned int *)((byte *)pDebugger + info.Debugger_pid);
                    if (pid != pid2)
                        continue;

                    void *pDebuggerRCThread = *(void **)((byte *)pDebugger + info.Debugger_pDebuggerRCThread);

                    // All allocations are pointer-size aligned
                    if (!PEInfo::IsAlignedPointer(pDebuggerRCThread))
                        continue;

                    // Make sure it points back to Debugger
                    void *pDebugger2 = *(void **)((byte *)pDebuggerRCThread + info.DebuggerRCThread_pDebugger);
                    if (pDebugger != pDebugger2)
                        continue;

                    return pDebuggerRCThread;
                }
                catch (...) {
                }
            }
        }
        catch (...) {
        }
        return nullptr;
    }

    /*
     * PE helper code. Written by de4dot@gmail.com
     * This code is in the public domain.
     * Official site: https://github.com/0xd4d/antinet
     */

    AntiManagedDebugger::PEInfo *AntiManagedDebugger::PEInfo::GetCLR() {
        auto clrAddr = GetCLRAddress();
        if (clrAddr == nullptr)
            return nullptr;
        return new PEInfo(clrAddr);
    }

    HMODULE AntiManagedDebugger::PEInfo::GetCLRAddress() {
        if (Environment::Version->Major == 2)
            return GetModuleHandleW(L"mscorwks.dll");
        return GetModuleHandleW(L"clr.dll");
    }

    AntiManagedDebugger::PEInfo::PEInfo(void *addr) {
        imageBase = addr;
        Initialize();
    }

    void AntiManagedDebugger::PEInfo::Initialize() {
        byte *p = (byte *)imageBase;
        p += *(unsigned int *)(p + 0x3C);    // Get NT headers
        p += 4 + 2;                          // Skip magic + machine
        numSects = *(unsigned short *)p;
        p += 2 + 0x10;                       // Skip the rest of file header
        bool is32 = *(unsigned short *)p == 0x010B;
        unsigned int sizeOfImage = *(unsigned int *)(p + 0x38);
        imageEnd = new void *((byte *)imageBase + sizeOfImage);
        p += is32 ? 0x60 : 0x70;             // Skip optional header
        p += 0x10 * 8;                       // Skip data dirs
        sectionsAddr = new void *(p);
    }

    bool AntiManagedDebugger::PEInfo::IsValidImageAddress(void *addr, unsigned int size) {
        if (addr < (void *)imageBase)
            return false;
        if (addr >= (void *)imageEnd)
            return false;

        if (size != 0) {
            if ((byte *)addr + size < (void *)addr)
                return false;
            if ((byte *)addr + size > (void *)imageEnd)
                return false;
        }
        return true;
    }

    bool AntiManagedDebugger::PEInfo::FindSection(std::string name, void *&sectionStart, unsigned int &sectionSize) {
        name += "\0\0\0\0\0\0\0\0";
        for (int i = 0; i < numSects; i++) {
            byte *p = (byte *)sectionsAddr + i * 0x28;
            if (!CompareSectionName(p, name.c_str()))
                continue;

            sectionStart = new void *((byte *)imageBase + *(unsigned int *)(p + 12));
            sectionSize = max(*(unsigned int *)(p + 8), *(unsigned int *)(p + 16));
            return true;
        }

        sectionStart = nullptr;
        sectionSize = 0;
        return false;
    }

    bool AntiManagedDebugger::PEInfo::CompareSectionName(byte *sectionName, const char *nameBytes) {
        for (int i = 0; i < 8; i++) {
            if (*sectionName != nameBytes[i])
                return false;
            sectionName++;
        }
        return true;
    }

    // Checks whether a pointer is aligned
    bool AntiManagedDebugger::PEInfo::IsAlignedPointer(void *addr) {
        return ((unsigned int)addr & (sizeof(void *) - 1)) == 0;
    }
}

