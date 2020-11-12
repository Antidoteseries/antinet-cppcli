/*
*
* Copyright (c) 2009-2011
* vol4ok <admin@vol4ok.net> PGP KEY ID: 26EC143CCDC61C9D
*

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General License for more details.

You should have received a copy of the GNU General License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#ifndef LDASM_H
#define LDASM_H
#include "pch.h"

namespace antinet {

    struct ldasm_data {
        byte flags;
        byte rex;
        byte modrm;
        byte sib;
        byte opcd_offset;
        byte opcd_size;
        byte disp_offset;
        byte disp_size;
        byte imm_offset;
        byte imm_size;
    };

    namespace Ldasm {
        /*
         Instruction format:

         | prefix | REX | opcode | modR/M | SIB | disp8/16/32 | imm8/16/32/64 |

         */
        enum :byte {
            F_INVALID = 0x01,
            F_PREFIX = 0x02,
            F_REX = 0x04,
            F_MODRM = 0x08,
            F_SIB = 0x10,
            F_DISP = 0x20,
            F_IMM = 0x40,
            F_RELATIVE = 0x80,
            OP_NONE = 0x00,
            OP_INVALID = 0x80,
            OP_DATA_I8 = 0x01,
            OP_DATA_I16 = 0x02,
            OP_DATA_I16_I32 = 0x04,
            OP_DATA_I16_I32_I64 = 0x08,
            OP_EXTENDED = 0x10,
            OP_RELATIVE = 0x20,
            OP_MODRM = 0x40,
            OP_PREFIX = 0x80
        };

        extern byte flags_table[256];
        extern byte flags_table_ex[256];

        byte cflags(byte op);
        byte cflags_ex(byte op);

        unsigned int ldasm(void *code, ldasm_data *ld, bool is64);
    };

}

#endif