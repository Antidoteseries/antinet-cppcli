#ifndef ANTI_MANAGERED_DEBUGGER_H
#define ANTI_MANAGERED_DEBUGGER_H

#include <Windows.h>
#include "pch.h"

namespace antinet
{
    class Info_CLR {
    public:
        // Offset in Debugger of pointer to DebuggerRCThread.
        // See Debugger::Startup() (after creating DebuggerRCThread).
        int Debugger_pDebuggerRCThread;

        // Offset in Debugger of the pid.
        // See Debugger::Debugger().
        int Debugger_pid;

        // Offset in DebuggerRCThread of pointer to Debugger.
        // See DebuggerRCThread::DebuggerRCThread().
        int DebuggerRCThread_pDebugger;

        // Offset in DebuggerRCThread of pointer to DebuggerIPCControlBlock.
        // See DebuggerRCThread::Start() after it creates the thread..
        int DebuggerRCThread_pDebuggerIPCControlBlock;

        // Offset in DebuggerRCThread of keep-looping boolean (1 byte).
        // See Debugger::StopDebugger() or one of the first methods it calls.
        int DebuggerRCThread_shouldKeepLooping;

        // Offset in DebuggerRCThread of event to signal to wake it up.
        // See Debugger::StopDebugger() or one of the first methods it calls.
        int DebuggerRCThread_hEvent1;

        Info_CLR(int Debugger_pDebuggerRCThread, int Debugger_pid, int DebuggerRCThread_pDebugger, int DebuggerRCThread_pDebuggerIPCControlBlock, int DebuggerRCThread_shouldKeepLooping, int DebuggerRCThread_hEvent1)
        {
            this->Debugger_pDebuggerRCThread = Debugger_pDebuggerRCThread;
            this->Debugger_pid = Debugger_pid;
            this->DebuggerRCThread_pDebugger = DebuggerRCThread_pDebugger;
            this->DebuggerRCThread_pDebuggerIPCControlBlock = DebuggerRCThread_pDebuggerIPCControlBlock;
            this->DebuggerRCThread_shouldKeepLooping = DebuggerRCThread_shouldKeepLooping;
            this->DebuggerRCThread_hEvent1 = DebuggerRCThread_hEvent1;
        }
    };

    class AntiManagedDebugger
    {
    public:
        static bool Initialize();
        static void *FindDebuggerRCThreadAddress(Info_CLR info);
        static Info_CLR Getinfo();

        class PEInfo {
        private:
            void *imageBase;
            void *imageEnd;
            void *sectionsAddr;
            int numSects;

        public:
            static PEInfo *GetCLR();
            static HMODULE GetCLRAddress();
            static bool IsAlignedPointer(void *addr);

            PEInfo(void *addr);

            void Initialize();

            bool IsValidImageAddress(void *addr, unsigned int size);
            bool FindSection(std::string name, void *&sectionStart, unsigned int &sectionSize);
            bool CompareSectionName(byte *sectionName, const char *nameBytes);
        };
    };
}

#endif // !ANTI_MANAGERED_DEBUGGER