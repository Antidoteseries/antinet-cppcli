#ifndef ANTI_DEBUGGER_H
#define ANTI_DEBUGGER_H

#include "pch.h"
#include "ldasm.h"
#include <Windows.h>

namespace antinet {
    class AntiDebugger {
    private:
        bool _isManagedDebuggerPrevented;
        bool _isManagedInitialized;
        byte *_pIsDebuggerAttached;
        unsigned int _isDebuggerAttachedLength;
        unsigned int _isDebuggerAttachedCrc32;

        bool _isDebuggerAttached();
        void InitializeManaged();
        void CopyOpcode(ldasm_data *pLdasmData, void *pCode, byte *opcodes, unsigned int offset);

        class PEInfo {
        private:
            void *_pPEImage;
            unsigned int _sectionsCount;
            IMAGE_SECTION_HEADER *_pSectionHeaders;

        public:
            void *PEImage()
            {
                return _pPEImage;
            }

            unsigned int SectionsCount()
            {
                return _sectionsCount;
            }

            IMAGE_SECTION_HEADER *SectionHeaders()
            {
                return _pSectionHeaders;
            }

            PEInfo(byte *pPEImage);
            unsigned int ToFOA(unsigned int rva);
        };

    public:
        bool PreventManagedDebugger();

        bool HasDebugger();

        bool HasUnmanagedDebugger();

        bool HasManagedDebugger();
    };  
}
#endif