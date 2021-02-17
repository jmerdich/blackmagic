/*
 * This file is part of the Black Magic Debug project.
 *
 * Copyright (C) 2017  Black Sphere Technologies Ltd.
 * Written by Gareth McMullin <gareth@blacksphere.co.nz>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * This file provides common register and arch definitions RISC-V platforms.
 * 
 * The RISC-V debug spec has two versions in common use, 0.11 and 0.13. Things
 * are not expected to diverge much after 0.13, so anything marked '013' means
 * '0.13 and above'. Common things between the two versions will not be marked
 * with a version (but may use the newer name even in code targeting 0.11)
 * 
 * 0.11 specifically means version 0.11nov12 (2016-11-12)
 * 0.13 speciifcally means commit b4f1f43 (2017-06-08)
 */

#pragma once

/**************************************
*     RISC-V JTAG DTM Registers
**************************************/

// JTAG register offset
#define IR_IDCODE 0x01
#define IR_DTMCS  0x10 /* called DTMCONTROL in 0.11 */
#define IR_DMI    0x11 /* called DBUS in 0.11 */
#define IR_BYPASS 0x1f


// DTMCS fields common to 0.11 and 0.13
#define DTMCS_VERSION_SHIFT   0
#define DTMCS_DMIRESET_SHIFT 16

#define DTMCS_VERSION_MASK   0x0000000f
#define DTMCS_DMIRESET_MASK  0x00010000

// DTMCS (DTMCONTROL) fields specific to 0.11
#define DTMCS_011_LOABITS_SHIFT   4
#define DTMCS_011_DBUSSTAT_SHIFT  8
#define DTMCS_011_IDLE_SHIFT     10
#define DTMCS_011_HIABITS_SHIFT  13

#define DTMCS_011_LOABITS_MASK   0x000000f0
#define DTMCS_011_DBUSSTAT_MASK  0x00000300
#define DTMCS_011_IDLE_MASK      0x00001c00
#define DTMCS_011_HIABITS_MASK   0x00006000


// DTMCS fields specific to 0.13
#define DTMCS_013_ABITS_SHIFT         4
#define DTMCS_013_DMISTAT_SHIFT      10
#define DTMCS_013_IDLE_SHIFT         12
#define DTMCS_013_DMIHARDRESET_SHIFT 17

#define DTMCS_013_ABITS_MASK         0x000003f0
#define DTMCS_013_DMISTAT_MASK       0x00000c00
#define DTMCS_013_IDLE_MASK          0x00007000
#define DTMCS_013_DMIHARDRESET_MASK  0x00020000

// DMI (DBUS on 0.11) opcodes
#define DMI_OP_NOP   0
#define DMI_OP_READ  1
#define DMI_OP_WRITE 2

// result codes share the same bits as opcode, but are read instead of written
#define DMI_RES_SUCCESS 0
#define DMI_RES_FAILED  2 // sticky!
#define DMI_RES_TOOSOON 3 // sticky!

/**************************************
*  RISC-V Debug Module Bus Registers
**************************************/

// This needs an update for 0.13.
#define DBUS_011_DMCONTROL 0x10
#define DBUS_011_DMINFO    0x11

#define DMCONTROL_011_INTERRUPT (1ull << 33)
#define DMCONTROL_011_HALTNOT (1ull << 32)

/**************************************
*     RISC-V Instruction encoding
**************************************/

#define OP_ITYPE(opcode, funct, rd, imm, rs1) \
                 ((opcode) | ((funct) << 12) | ((rd) << 7) | ((rs1) << 15) | ((imm) << 20))
#define OP_STYPE(opcode, funct, rs1, imm, rs2) \
                 ((opcode) | ((funct) << 12) | ((rs1) << 15) | ((rs2) << 20) | \
		  (((imm) & 0x1f) << 7) | (((imm) & 0xfe0) << 20))
#define OPCODE_LOAD   0x03
#define OPCODE_STORE  0x23
#define OPCODE_OP_IMM 0x13
#define OPCODE_JUMP   0x6f
#define OP_ADDI       0
#define LB(rd, imm, base) OP_ITYPE(OPCODE_LOAD, 0, rd, imm, base)
#define LH(rd, imm, base) OP_ITYPE(OPCODE_LOAD, 1, rd, imm, base)
#define LW(rd, imm, base) OP_ITYPE(OPCODE_LOAD, 2, rd, imm, base)
#define SB(rs, imm, base) OP_STYPE(OPCODE_STORE, 0, base, imm, rs)
#define SH(rs, imm, base) OP_STYPE(OPCODE_STORE, 1, base, imm, rs)
#define SW(rs, imm, base) OP_STYPE(OPCODE_STORE, 2, base, imm, rs)
#define J(imm)            (OPCODE_JUMP | ((imm) << 20))
#define ADDI(rd, rs, imm) OP_ITYPE(OPCODE_OP_IMM, OP_ADDI, rd, imm, rs)
#define S0 8
#define S1 9
#define T0 5
#define JRESUME(n)        (J(0x804 - (0x400 + ((n) * 4))))

/**************************************
*            RISC-V CSRs
**************************************/

#define CSR_TSELECT  0x7a0
#define CSR_MCONTROL 0x7a1
#define CSR_TDATA2   0x7a2

#define CSR_DCSR     0x7b0
#define CSR_DPC      0x7b1
#define CSR_DSCRATCH 0x7b2

#define CSR_MCONTROL_DMODE        (1<<(32-5))
#define CSR_MCONTROL_ENABLE_MASK  (0xf << 3)
#define CSR_MCONTROL_R            (1 << 0)
#define CSR_MCONTROL_W            (1 << 1)
#define CSR_MCONTROL_X            (1 << 2)
#define CSR_MCONTROL_RW           (CSR_MCONTROL_R | CSR_MCONTROL_W)
#define CSR_MCONTROL_RWX          (CSR_MCONTROL_RW | CSR_MCONTROL_X)
#define CSR_MCONTROL_ACTION_DEBUG (1 << 12)

#define CSR_DCSR_STEP    (1 << 2)
#define CSR_DCSR_HALT    (1 << 3)
#define CSR_DCSR_NDRESET (1 << 29)


/**************************************
*     GDB Target Descriptions
**************************************/
static const char tdesc_rv32[] =
"<?xml version=\"1.0\"?>"
"<target>"
"  <architecture>riscv:rv32</architecture>"
"</target>";

/**************************************
*     Driver-private structs
**************************************/

struct riscv_dtm {
	uint8_t dtm_index;
	uint8_t version; /* As read from dmtcontrol */
	uint8_t abits; /* Debug bus address bits (6 bits wide) */
	uint8_t idle; /* Number of cycles required in run-test/idle */
	uint8_t dramsize; /* Size of debug ram in words - 1 */
	bool error;
	bool exception;
	uint64_t lastdbus;
	bool halt_requested;
	uint32_t saved_s1;
};