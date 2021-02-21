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

typedef enum {
	ABSTRACTCS_CMDERR_NONE = 0,
	ABSTRACTCS_CMDERR_BUSY = 1,
	ABSTRACTCS_CMDERR_NOT_SUPPORTED = 2,
	ABSTRACTCS_CMDERR_EXCEPTION = 3,
	ABSTRACTCS_CMDERR_HALT_RESUME = 4,
	ABSTRACTCS_CMDERR_BUS = 5,
	ABSTRACTCS_CMDERR_OTHER = 7,
} ABSTRACTCS_CMDERR_T;

#define ABSTRACT_GPR_START 0x1000
typedef enum {
	RV_GPR_x0 = 0,
	RV_GPR_s0 = 8
	// and much more
} RV_GPR_T;

#define GET_FIELD(v, name) ((v & name) >> name##_OFFSET)
#define SET_FIELD(v, name) ((v << name##_OFFSET) & name)

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
	//DEBUG("DTM out %"PRIx64"\n", dmi);
	jtag_dev_shift_dr(&jtag_proc, dtm->dtm_index, (void*)&ret, (const void*)&dmi,
					  DTM_DMI_ADDRESS_OFFSET + dtm->abits);
	//DEBUG("DTM in %"PRIx64"\n", ret);
	switch (GET_FIELD(ret, DTM_DMI_OP)) {
	case DMI_RES_TOOSOON:
		riscv_dtm_reset(dtm);
		jtag_dev_write_ir(&jtag_proc, dtm->dtm_index, DTM_DMI);
		DEBUG("DTM retry out %"PRIx64"\n", dmi);
		jtag_dev_shift_dr(&jtag_proc, dtm->dtm_index,
		                  (void*)&ret, (const void*)&dtm->lastdbus,
		                  dtm->abits + DTM_DMI_ADDRESS_OFFSET);
		DEBUG("DTM in %"PRIx64"\n", ret);
		jtag_proc.jtagtap_tms_seq(0, dtm->idle++);
		goto retry;
	case DMI_RES_SUCCESS:
		dtm->lastdbus = dmi;
		break;
	case DMI_RES_FAILED:
	default:
		DEBUG("DTM got sticky error!");
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
	uint8_t abits = dtm->abits;
	riscv_dtm_low_access(dtm, SET_FIELD((uint64_t)addr, DTM_DMI_ADDRESS) |
	                          SET_FIELD((uint64_t)data, DTM_DMI_DATA) |
							  DMI_OP_WRITE);
	riscv_dtm_low_access(dtm, DMI_OP_NOP);
}

static ABSTRACTCS_CMDERR_T riscv_abstract_wait(struct riscv_dtm* dtm) {
	uint32_t abstractcs;
	do {
		abstractcs = riscv_dtm_read(dtm, DMI_ABSTRACTCS);
	} while (GET_FIELD(abstractcs, DMI_ABSTRACTCS_BUSY));

	uint8_t cmderr = GET_FIELD(abstractcs, DMI_ABSTRACTCS_CMDERR);

	if (cmderr == 0) {
		return ABSTRACTCS_CMDERR_NONE;
	} else {
		DEBUG("Abstract command got error %d\n", cmderr);
		// Clear sticky error
		riscv_dtm_write(dtm, DMI_ABSTRACTCS, DMI_ABSTRACTCS_CMDERR);
		return cmderr;
	}

}

static ABSTRACTCS_CMDERR_T riscv_abstract_reg_read32(struct riscv_dtm *dtm, uint16_t absreg, uint32_t* data) {
	if (dtm->v013.datacount == 0) {
		return ABSTRACTCS_CMDERR_NOT_SUPPORTED;
	}
	DEBUG("Reading abstract register 0x%04x", absreg);
	uint32_t reg_cmd = SET_FIELD(2 /* = 32b */, AC_ACCESS_REGISTER_SIZE) |
	                   SET_FIELD(absreg, AC_ACCESS_REGISTER_REGNO) |
					   AC_ACCESS_REGISTER_TRANSFER;
	riscv_dtm_write(dtm, DMI_COMMAND, reg_cmd);

	ABSTRACTCS_CMDERR_T err = riscv_abstract_wait(dtm);
	if (err == ABSTRACTCS_CMDERR_NONE) {
		*data = riscv_dtm_read(dtm, DMI_DATA0);
		DEBUG("... got %04x", *data);
	}
	DEBUG("\n");
	return err;
}

static ABSTRACTCS_CMDERR_T riscv_abstract_reg_write32(struct riscv_dtm *dtm, uint16_t absreg, uint32_t data) {
	if (dtm->v013.datacount == 0) {
		return ABSTRACTCS_CMDERR_NOT_SUPPORTED;
	}

	DEBUG("Writing 0x%08x to abstract register 0x%04x\n", data, absreg);
	riscv_dtm_write(dtm, DMI_DATA0, data);

	uint32_t reg_cmd = SET_FIELD(2 /* = 32b */, AC_ACCESS_REGISTER_SIZE) |
	                   SET_FIELD(absreg, AC_ACCESS_REGISTER_REGNO) |
					   AC_ACCESS_REGISTER_WRITE |
					   AC_ACCESS_REGISTER_TRANSFER;
	riscv_dtm_write(dtm, DMI_COMMAND, reg_cmd);

	return riscv_abstract_wait(dtm);
}


static ABSTRACTCS_CMDERR_T riscv_abstract_exec(struct riscv_dtm *dtm,
											   uint32_t* prog,
											   uint8_t progsizedw) {
	if (dtm->v013.progsize < progsizedw + 1) {
		return ABSTRACTCS_CMDERR_NOT_SUPPORTED;
	}
	// Todo: some implementations require a save/restore of dpc

	DEBUG("Executing buffer:\n");
	for (int i = 0; i < progsizedw; i++) {
		DEBUG("  %02d: %08x\n", i, prog[i]);
		riscv_dtm_write(dtm, DMI_PROGBUF0 + i, prog[i]);
	}

	// 0: 73 00 10 00                   ebreak
	uint32_t ebreak = 0x00100073;

	riscv_dtm_write(dtm, DMI_PROGBUF0 + progsizedw, ebreak);
	riscv_dtm_write(dtm, DMI_COMMAND, AC_ACCESS_REGISTER_POSTEXEC);
	return riscv_abstract_wait(dtm);
}


static bool riscv_csr_read32(struct riscv_dtm *dtm, uint16_t csr, uint32_t* data) {
	if (dtm->detectedFeatures.absCsrAccess)
	{
		// If we can, pull it directly
		ABSTRACTCS_CMDERR_T res = riscv_abstract_reg_read32(dtm, csr, data);

		switch (res) {
			case ABSTRACTCS_CMDERR_NONE:
				return true;
			case ABSTRACTCS_CMDERR_NOT_SUPPORTED:
				dtm->detectedFeatures.absCsrAccess = false;
				return riscv_csr_read32(dtm, csr, data);
			default:
				DEBUG("Got error %d accessing csr %04x via abstract reg\n", res, csr);
				return false;
		}
	}

	assert(dtm->v013.progsize >= 1);
	assert(dtm->v013.datacount >= 1);

	uint32_t saved_s0; 
	ABSTRACTCS_CMDERR_T err = riscv_abstract_reg_read32(dtm, ABSTRACT_GPR_START + RV_GPR_s0, &saved_s0);
	if (err) {
		DEBUG("Error: failed to save s0 (code %d).\n", err);
		return false;
	}

	// csrr s0, 0x000
	uint32_t csrr = 0x00002473 | (csr << 20);
	err = riscv_abstract_exec(dtm, &csrr, 1);
	if (err) {
		DEBUG("Error: failed to execute code to read csr (code %d).\n", err);
		return false;
	}

	err = riscv_abstract_reg_read32(dtm, ABSTRACT_GPR_START + RV_GPR_s0, data);
	if (err) {
		DEBUG("Error: failed to read csr data (code %d).\n", err);
		return false;
	}

	err = riscv_abstract_reg_write32(dtm, ABSTRACT_GPR_START + RV_GPR_s0, saved_s0);
	if (err) {
		DEBUG("Error: failed to restore s0 (code %d).\n", err);
		return false;
	}

	return true;
}

static bool riscv_csr_setbits(struct riscv_dtm *dtm, uint16_t csr, uint32_t mask) {
	assert(dtm->v013.progsize >= 1);
	assert(dtm->v013.datacount >= 1);

	uint32_t saved_s0; 
	ABSTRACTCS_CMDERR_T err = riscv_abstract_reg_read32(dtm, ABSTRACT_GPR_START + RV_GPR_s0, &saved_s0);
	if (err) {
		DEBUG("Error: failed to save s0 (code %d).\n", err);
		return false;
	}

	err = riscv_abstract_reg_write32(dtm, ABSTRACT_GPR_START + RV_GPR_s0, mask);
	if (err) {
		DEBUG("Error: failed to write csr mask (code %d).\n", err);
		return false;
	}

	// csrs 0x000, s0
	uint32_t csrs = 0x00042073 | (csr << 20);
	err = riscv_abstract_exec(dtm, &csrs, 1);
	if (err) {
		DEBUG("Error: failed to execute code to toggle csr (code %d).\n", err);
		return false;
	}

	err = riscv_abstract_reg_write32(dtm, ABSTRACT_GPR_START + RV_GPR_s0, saved_s0);
	if (err) {
		DEBUG("Error: failed to restore s0 (code %d).\n", err);
		return false;
	}

	return true;
}

static bool riscv_csr_clearbits(struct riscv_dtm *dtm, uint16_t csr, uint32_t mask) {
	assert(dtm->v013.progsize >= 1);
	assert(dtm->v013.datacount >= 1);

	uint32_t saved_s0; 
	ABSTRACTCS_CMDERR_T err = riscv_abstract_reg_read32(dtm, ABSTRACT_GPR_START + RV_GPR_s0, &saved_s0);
	if (err) {
		DEBUG("Error: failed to save s0 (code %d).\n", err);
		return false;
	}

	err = riscv_abstract_reg_write32(dtm, ABSTRACT_GPR_START + RV_GPR_s0, mask);
	if (err) {
		DEBUG("Error: failed to write csr mask (code %d).\n", err);
		return false;
	}

	// csrc 0x000, s0
	uint32_t csrc = 0x00043073 | (csr << 20);
	err = riscv_abstract_exec(dtm, &csrc, 1);
	if (err) {
		DEBUG("Error: failed to execute code to toggle csr (code %d).\n", err);
		return false;
	}

	err = riscv_abstract_reg_write32(dtm, ABSTRACT_GPR_START + RV_GPR_s0, saved_s0);
	if (err) {
		DEBUG("Error: failed to restore s0 (code %d).\n", err);
		return false;
	}

	return true;
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

static void riscv_halt_request(target* t) {
	struct riscv_dtm* dtm = (struct riscv_dtm*)t->priv;
	riscv_dtm_write(dtm, DMI_DMCONTROL, DMI_DMCONTROL_DMACTIVE |
										DMI_DMCONTROL_HALTREQ);
	// Don't actually wait, the polling logic will take care of it.
}

static void riscv_halt_resume(target* t, bool step) {
	struct riscv_dtm* dtm = (struct riscv_dtm*)t->priv;

	// Handle step logic
	if (GET_FIELD(dtm->v013.last_dcsr, CSR_DCSR_STEP) != step) {
		bool success = false;
		if (step) {
			success = riscv_csr_setbits(dtm, CSR_DCSR, CSR_DCSR_STEP);
			if (success) {
				dtm->v013.last_dcsr |= CSR_DCSR;
			}
		} else {
			success = riscv_csr_clearbits(dtm, CSR_DCSR, CSR_DCSR_STEP);
			if (success) {
				dtm->v013.last_dcsr &= CSR_DCSR;
			}
		}

		if (!success) {
			DEBUG("Failed to set step=%d!\n", step);
			// continue anyhow
		}
	}

	riscv_dtm_write(dtm, DMI_DMCONTROL, DMI_DMCONTROL_DMACTIVE |
										DMI_DMCONTROL_RESUMEREQ);

	// Wait for resume to be acknowledged (target may halt again immediately)
	uint32_t dmstatus;
	do {
		dmstatus = riscv_dtm_read(dtm, DMI_DMSTATUS);
	} while (GET_FIELD(dmstatus, DMI_DMSTATUS_ALLRESUMEACK) == 0);
}

static enum target_halt_reason riscv_halt_poll(target* t, target_addr* watch) {
	(void)watch; // watchpoints not done, set it to hit addr when it is
	struct riscv_dtm* dtm = (struct riscv_dtm*)t->priv;

	uint32_t halted_harts = riscv_dtm_read(dtm, DMI_HALTSUM);
	if (halted_harts == 0) {
		return TARGET_HALT_RUNNING;
	}

	uint32_t dcsr;
	if (riscv_csr_read32(dtm, CSR_DCSR, &dcsr)) {
		dtm->v013.last_dcsr = dcsr;
		switch (GET_FIELD(dcsr, CSR_DCSR_CAUSE)) {
			case 1: // sw breakpoint
			case 2: // hw breakpoint/watchpoint
				return TARGET_HALT_BREAKPOINT;
			case 3:
				return TARGET_HALT_REQUEST;
			case 4:
				return TARGET_HALT_STEPPING;
			default:
				return TARGET_HALT_ERROR;
		}
	} else {
		// Reg read failed?!?
		return TARGET_HALT_ERROR;
	}
}

static bool riscv_attach(target *t)
{
	target_halt_request(t);
	return true;
}

static void riscv_detach(target *t)
{
	target_halt_resume(t, false);
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

	if (dmstatus & (1 << 18)) {
		// ackhavereset
		riscv_dtm_write(&dtm, DMI_DMCONTROL, 0x10000000 /* ackhavereset */ |
		                                     DMI_DMCONTROL_DMACTIVE);
	}

	uint32_t abstractcs = riscv_dtm_read(&dtm, DMI_ABSTRACTCS);
	dtm.v013.progsize = GET_FIELD(abstractcs, DMI_ABSTRACTCS_PROGSIZE);
	DEBUG("\tprogsize = %d (%d bytes)\n", dtm.v013.progsize, dtm.v013.progsize * 4);
	dtm.v013.datacount = GET_FIELD(abstractcs, DMI_ABSTRACTCS_DATACOUNT);
	DEBUG("\tdatacount = %d\n", dtm.v013.datacount);

	// Some features can only be detected after they fail the first time
	dtm.detectedFeatures.absCsrAccess = 1;
	dtm.detectedFeatures.absOtherRegAccess = 1;
	dtm.detectedFeatures.absQuickAccess = 1;
	dtm.detectedFeatures.absMemAccess = 1;
	
	// Initialize 'last' values to speed up RMW
	riscv_csr_read32(&dtm, CSR_DCSR, &dtm.v013.last_dcsr);
	DEBUG("\tdcsr = 0x%08x\n", dtm.v013.last_dcsr);

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
	t->halt_poll = riscv_halt_poll;
	t->halt_request = riscv_halt_request;
	t->halt_resume = riscv_halt_resume;
	t->attach = riscv_attach;
	t->detach = riscv_detach;

/*
	t->mem_read = riscv_mem_read;
	t->mem_write = riscv_mem_write;
	t->check_error = riscv_check_error;
	t->reg_read = riscv_reg_read;
	t->reg_write = riscv_reg_write;
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
