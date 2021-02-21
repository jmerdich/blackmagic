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
 * This file provides common implementation structs for RISC-V platforms.
 * 
 * The RISC-V debug spec has two versions in common use, 0.11 and 0.13. Things
 * are not expected to diverge much after 0.13, so anything marked 'riscv' means
 * '0.13 and above', whereas 0.11 has a separate implementation.
 * 
 * The only known device to use 0.11 is the SiFive FE310g000 (which also happens
 * to be the first generally-available RISC-V device).
 * 
 * 0.11 specifically means version 0.11nov12 (2016-11-12)
 * 0.13 speciifcally means commit b4f1f43 (2017-06-08)
 */

#ifndef __RISCV_H
#define __RISCV_H

#include "jtag_scan.h"
#include "target.h"

void riscv_jtag_handler(uint8_t jd_index, uint32_t j_idcode);

bool riscv_011_init(uint8_t jd_index, uint32_t idcode, uint32_t dtmcontrol);

/**************************************
*     Driver-private structs
**************************************/

struct riscv_dtm {
	uint8_t dtm_index;
	uint8_t version; /* As read from dmtcontrol */
	uint8_t abits; /* Debug bus address bits (6 bits wide) */
	uint8_t idle; /* Number of cycles required in run-test/idle */
    uint32_t idcode;
	uint64_t lastdbus;
	uint32_t saved_s1;
	bool error;
	bool exception;
	bool halt_requested;
    bool is_halted;
    bool halt_pushed;
    uint8_t halt_pushed_level;
    struct {
        uint32_t absCsrAccess : 1;
        uint32_t absOtherRegAccess : 1;
        uint32_t absQuickAccess : 1;
        uint32_t absMemAccess : 1;
        uint32_t autoExecProg : 1;
        uint32_t autoExecData : 1;
        uint32_t reserved : 26;
    } detectedFeatures;
    union {
        struct {
            uint8_t dramsize; /* Size of debug ram in words - 1 */
        } v011;
        struct {
            uint32_t last_dcsr;
            uint8_t progsize;
            uint8_t datacount;
        } v013;
    };
};

/**************************************
*     GDB Target Descriptions
**************************************/
static const char tdesc_rv32[] =
"<?xml version=\"1.0\"?>"
"<target>"
"  <architecture>riscv:rv32</architecture>"
"</target>";

#endif
