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
 * According to risv-debug-spec 0.13 - b4f1f43 (2017-06-08)
 */
#define DEBUG DEBUG_WARN

#include "general.h"
#include "jtagtap.h"
#include "jtag_scan.h"
#include "target.h"
#include "target_internal.h"
#include "riscv.h"
#include "riscv_debug_defines.h"

// Enums for debug regs
// DMI opcodes
#define DMI_OP_NOP   0
#define DMI_OP_READ  1
#define DMI_OP_WRITE 2

// result codes share the same bits as opcode, but are read instead of written
#define DMI_RES_SUCCESS 0
#define DMI_RES_FAILED  2 // sticky!
#define DMI_RES_TOOSOON 3 // sticky!

#define GET_FIELD(v, name) ((v & name) >> name##_OFFSET)

#include <assert.h>

static void riscv_dtm_reset(struct riscv_dtm *dtm)
{
	jtag_dev_write_ir(&jtag_proc, dtm->dtm_index, DTM_DTMCS);
	uint32_t dtmcs = DTM_DTMCS_DMIRESET;
	jtag_dev_shift_dr(&jtag_proc, dtm->dtm_index, (void*)&dtmcs, (void*)&dtmcs, 32);
	DEBUG("after dtm soft reset: dtmcs = 0x%08x\n", dtmcs);
}

static void riscv_dtm_hard_reset(struct riscv_dtm *dtm)
{
	jtag_dev_write_ir(&jtag_proc, dtm->dtm_index, DTM_DTMCS);
	uint32_t dtmcs = DTM_DTMCS_DMIHARDRESET;
	jtag_dev_shift_dr(&jtag_proc, dtm->dtm_index, (void*)&dtmcs, (void*)&dtmcs, 32);
	DEBUG("after dtm hard reset: dtmcs = 0x%08x\n", dtmcs);
}

static uint32_t riscv_dtm_low_access(struct riscv_dtm *dtm, uint64_t dmi)
{
	if (dtm->error)
		return 0;

	uint64_t ret = 0;
	/* Do not smash the stack if abits has gone astray!*/
	if (dtm->abits > (64-DTM_DMI_ADDRESS_OFFSET)) {
		DEBUG("Abits overflow in  riscv_dtm_low_access: %d\n", dtm->abits);
		return 0;
	}
retry:
	DEBUG("out %"PRIx64"\n", dmi);
	jtag_dev_shift_dr(&jtag_proc, dtm->dtm_index, (void*)&ret, (const void*)&dmi,
					  DTM_DMI_ADDRESS_OFFSET + dtm->abits);
	DEBUG("in %"PRIx64"\n", ret);
	switch (GET_FIELD(ret, DTM_DMI_OP)) {
	case DMI_RES_TOOSOON:
		riscv_dtm_reset(dtm);
		jtag_dev_write_ir(&jtag_proc, dtm->dtm_index, DTM_DMI);
		DEBUG("retry out %"PRIx64"\n", dmi);
		jtag_dev_shift_dr(&jtag_proc, dtm->dtm_index,
		                  (void*)&ret, (const void*)&dtm->lastdbus,
		                  dtm->abits + DTM_DMI_ADDRESS_OFFSET);
		DEBUG("in %"PRIx64"\n", ret);
		jtag_proc.jtagtap_tms_seq(0, dtm->idle++);
		goto retry;
	case DMI_RES_SUCCESS:
		dtm->lastdbus = dmi;
		break;
	case DMI_RES_FAILED:
	default:
		DEBUG("Set sticky error!");
		dtm->error = true;
		return 0;
	}
	if ((GET_FIELD(dmi, DTM_DMI_OP) != DMI_OP_NOP) && dtm->idle) {
		jtag_proc.jtagtap_tms_seq(0, dtm->idle - 1);
	}
	return GET_FIELD(ret, DTM_DMI_DATA);
}

static uint32_t riscv_dtm_read(struct riscv_dtm *dtm, uint32_t addr)
{
	riscv_dtm_low_access(dtm, ((uint64_t)addr << DTM_DMI_ADDRESS_OFFSET) | DMI_OP_READ);
	return riscv_dtm_low_access(dtm, DMI_OP_NOP);
}

static void riscv_dtm_write(struct riscv_dtm *dtm, uint32_t addr, uint32_t data)
{
	riscv_dtm_low_access(dtm, ((uint64_t)addr << DTM_DMI_ADDRESS_OFFSET) |
	                          ((uint64_t)data << DTM_DMI_DATA_OFFSET) |
							  DMI_OP_WRITE);
}

static void riscv_reset_target(target* t) {
	struct riscv_dtm* dtm = (struct riscv_dtm*)t->priv;
	DEBUG("Sending device/hart0 reset...\n");
	riscv_dtm_write(dtm, DMI_DMCONTROL, DMI_DMCONTROL_NDMRESET |
	                                    DMI_DMCONTROL_HARTRESET|
										DMI_DMCONTROL_DMACTIVE |
										DMI_DMCONTROL_HALTREQ);
	riscv_dtm_write(dtm, DMI_DMCONTROL, DMI_DMCONTROL_DMACTIVE |
	                                    DMI_DMCONTROL_HALTREQ);
	uint32_t dmcontrol;
	do {
		dmcontrol = riscv_dtm_read(dtm, DMI_DMCONTROL);
		DEBUG("Waiting for reset (dmcontrol=%0x08x)\n", dmcontrol);
	} while ((GET_FIELD(dmcontrol, DMI_DMCONTROL_HARTRESET) != 0) ||
	         (GET_FIELD(dmcontrol, DMI_DMCONTROL_NDMRESET) != 0));
	DEBUG("Device has reset!\n");
}

bool riscv_013_init(uint8_t jd_index, uint32_t j_idcode, uint32_t dtmcs) {
	struct riscv_dtm dtm = {};
	dtm.dtm_index = jd_index;
	dtm.idcode = j_idcode;
	dtm.abits = GET_FIELD(dtmcs, DTM_DTMCS_ABITS);
	dtm.idle = GET_FIELD(dtmcs, DTM_DTMCS_IDLE);
	DEBUG("abits = %d\n", dtm.abits);
	DEBUG("idle = %d\n", dtm.idle);
	DEBUG("dmistat = %d\n", GET_FIELD(dtmcs, DTM_DTMCS_DMISTAT));

	riscv_dtm_hard_reset(&dtm);

	jtag_dev_write_ir(&jtag_proc, jd_index, DTM_DMI);

	uint32_t dmstatus = riscv_dtm_read(&dtm, DMI_DMSTATUS);
	DEBUG("dmstatus = %"PRIx32"\n", dmstatus);
	uint8_t version = GET_FIELD(dmstatus, DMI_DMSTATUS_VERSION);
	DEBUG("\tversion = %d\n", version);
	if (version != 2)
		return false;

	uint8_t authenticated = GET_FIELD(dmstatus, DMI_DMSTATUS_AUTHENTICATED);
	DEBUG("\tauthenticated = %d\n", authenticated);
	if (authenticated != 1)
		return false;

	uint32_t abstractcs = riscv_dtm_read(&dtm, DMI_ABSTRACTCS);
	dtm.v013.progsize = GET_FIELD(abstractcs, DMI_ABSTRACTCS_PROGSIZE);
	DEBUG("\tprogsize = %d (%d bytes)\n", dtm.v013.progsize, dtm.v013.progsize * 4);
	dtm.v013.datacount = GET_FIELD(abstractcs, DMI_ABSTRACTCS_DATACOUNT);
	DEBUG("\tdatacount = %d\n", dtm.v013.datacount);

	/* Allocate and set up new target */
	struct riscv_dtm* saved_dtm = malloc(sizeof(dtm));
	if (!saved_dtm) {
		return false;
	}
	target *t = target_new();
	if (!t) {
		free(saved_dtm);
		return false;
	}
	t->priv = saved_dtm;
	t->priv_free = free;
	memcpy(t->priv, &dtm, sizeof(dtm));

	t->driver = "RISC-V 0.13";
	t->regs_size = 33 * 4;
	t->tdesc = tdesc_rv32;

	t->reset = riscv_reset_target;

/*
	t->mem_read = riscv_mem_read;
	t->mem_write = riscv_mem_write;
	t->attach = riscv_attach;
	t->detach = riscv_detach;
	t->check_error = riscv_check_error;
	t->reg_read = riscv_reg_read;
	t->reg_write = riscv_reg_write;
	t->halt_request = riscv_halt_request;
	t->halt_poll = riscv_halt_poll;
	t->halt_resume = riscv_halt_resume;
	t->breakwatch_set = riscv_breakwatch_set;
	t->breakwatch_clear = riscv_breakwatch_clear;
*/
	return true;

}

void riscv_jtag_handler(uint8_t jd_index, uint32_t j_idcode)
{
	uint32_t dtmcontrol = 0;
	(void)j_idcode;
	DEBUG("Scanning RISC-V jtag dev at pos %d, idcode %08" PRIx32 "\n",
		  jd_index, j_idcode);
	jtag_dev_write_ir(&jtag_proc, jd_index, DTM_DTMCS);
	jtag_dev_shift_dr(&jtag_proc, jd_index, (void*)&dtmcontrol, (void*)&dtmcontrol, 32);
	DEBUG("dtmcontrol = 0x%08x\n", dtmcontrol);
	uint8_t version = dtmcontrol & 0xf;

	switch (version) {
	case 0:
		riscv_011_init(jd_index, j_idcode, dtmcontrol);
	    break;
	case 1:
		DEBUG("Risc-V Debug 0.13.x is *very* experimental.\n");
		riscv_013_init(jd_index, j_idcode, dtmcontrol);
		break;
	default:
		DEBUG("Unsupported Risc-V Debug spec. Version is %d\n", version);
		return;
	}
}
