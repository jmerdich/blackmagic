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

/* This file implements debugging functionality specific to RISC-V targets.
 * According to risv-debug-spec 0.11nov12 November 12, 2016
 */
#define DEBUG DEBUG_WARN

#include "general.h"
#include "jtagtap.h"
#include "jtag_scan.h"
#include "target.h"
#include "target_internal.h"
#include "riscv_common.h"

#include <assert.h>

void riscv_jtag_handler(uint8_t jd_index, uint32_t j_idcode)
{
	uint32_t dtmcontrol = 0;
	(void)j_idcode;
	DEBUG("Scanning RISC-V jtag dev at pos %d, idcode %08" PRIx32 "\n",
		  jd_index, j_idcode);
	jtag_dev_write_ir(&jtag_proc, jd_index, IR_DTMCS);
	jtag_dev_shift_dr(&jtag_proc, jd_index, (void*)&dtmcontrol, (void*)&dtmcontrol, 32);
	DEBUG("dtmcontrol = 0x%08x\n", dtmcontrol);
	uint8_t version = dtmcontrol & 0xf;

	switch (version) {
	case 0:
		riscv_011_init(jd_index, j_idcode, dtmcontrol);
	    break;
	case 1:
		DEBUG("Risc-V Debug 0.13.x is *very* experimental.\n");
		assert(false);
		break;
	default:
		DEBUG("Unsupported Risc-V Debug spec. Version is %d\n", version);
		return;
	}
}
