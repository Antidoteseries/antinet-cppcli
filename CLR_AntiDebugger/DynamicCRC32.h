#ifndef DYNAMIC_CRC32_H
#define DYNAMIC_CRC32_H
#include "pch.h"

namespace antinet {

    class DynamicCrc32 {
    private:
        unsigned int *_table;
    public:
        DynamicCrc32();
        unsigned int Compute(byte *pData, unsigned int length);
    };

}
#endif