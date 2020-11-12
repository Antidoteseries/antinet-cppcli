#include "DynamicCRC32.h"

using namespace System;
namespace antinet
{
    DynamicCrc32::DynamicCrc32()
    {
        auto rand = gcnew Random;
        unsigned int seed = rand->Next();
        // Default is 0xEDB88320

        _table = new unsigned int[256];

        for (int i = 0; i < 256; i++) {
            unsigned int crc;

            crc = (unsigned int)i;
            for (int j = 8; j > 0; j--) {
                if ((crc & 1) == 1)
                    crc = (crc >> 1) ^ seed;
                else
                    crc >>= 1;
            }
            _table[i] = crc;
        }
    }

    unsigned int DynamicCrc32::Compute(byte *pData, unsigned int length)
    {
        unsigned int crc32;

        crc32 = 0xFFFFFFFF;
        for (unsigned int i = 0; i < length; i++)
            crc32 = (crc32 >> 8) ^ _table[(crc32 ^ pData[i]) & 0xFF];
        return ~crc32;
    }
}