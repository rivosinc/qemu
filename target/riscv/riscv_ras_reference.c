/*
 * RISC-V RAS (Reliability, Availability and Serviceability) block
 *
 * Copyright (c) 2023 Rivos Inc
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 or
 *  (at your option) any later version.
 */

#include "qemu/osdep.h"
#include "riscv_ras_reference.h"
#include "qemu/log.h"

int riscv_ras_read(RiscvRasComponentRegisters *regs, uintptr_t addr, uint64_t *out,
                        unsigned size)
{
    uint64_t val64 = 0;
    uint8_t *reg;

    if (addr + size > sizeof(RiscvRasComponentRegisters) ||
       ((addr & 0x7) + size) > 8) {
        return EINVAL;
    }

    reg = ((uint8_t *)regs) + addr;

    while (size--) {
        val64 <<= 8;
        val64 |= *(reg + size);
    }

    *out = val64;

    return 0;
}


static uint64_t riscv_ras_write_status(RiscvRasStatus old, RiscvRasStatus new)
{
    new.u64 &= RAS_STS_MASK;

    /* Only one error type can be injected. */
    if (new.ce + new.de + new.ue != 1) {
        return old.u64;
    }

    if (old.v == 0) {
        return new.u64;
    }

    /* Overwrite rules. */
   if (new.ce) {
       if (old.ce) {
           old.mo = 1;
           old.v = 0;
       } else {
           old.ce = 1;
       }
       new.u64 = old.u64;
   } else if (new.de && old.ue) {
       return old.u64;
   } else if (new.ue && old.ue) {
       new.mo = 1;
   }

    return new.u64;

}

int riscv_ras_write(RiscvRasComponentRegisters *regs, uintptr_t addr, uint64_t val,
                        unsigned size, bool *inject, bool *clrsts)
{
    RiscvRasErrorRecord *record;
    RiscvRasControl ctrl;
    uint64_t reg;

    if (addr + size > sizeof(RiscvRasComponentRegisters) ||
       ((addr & 0x7) + size) > 8) {
        return EINVAL;
    }

    if (addr < 32) {
        return 0;
    }

    reg = *(((uint64_t *)regs) + (addr / 8));

    /*
     * In order to handle a partial register write merge the new bytes
     * with the current value of the register.
     */
    for (int i = addr & 0x7; i < size + (addr & 0x7); i++) {
        reg &= ~((uint64_t)UINT8_MAX << 8 * i);
        reg |= (val & UINT8_MAX) << 8 * i;
        val >>= 8;
    }

    addr &= ~0x7;
    addr -= 64;
    record = &regs->records[addr / 32];
    addr = addr % 64;

    switch (addr) {
    case 0: /* control_i */
        ctrl.u64 = reg;
//        ctrl.u64 &= RAS_CTRL_MASK;
        if (ctrl.sinv) {
            record->status_i.v = 0;
            ctrl.sinv = 0;
            *clrsts = true;
        }
        if (ctrl.eid != 0 && record->control_i.eid == 0) {
            *inject = true;
        }
        record->control_i = ctrl;
        break;
    case 8: /* status_i */
        record->status_i.u64 =
            riscv_ras_write_status(record->status_i, (RiscvRasStatus)reg);
        break;
    /* XXX: Allow modification of addr_i and info_i only if status_i.v==0? */
    case 16: /* addr_i */
        record->addr_i = reg;
        break;
    case 24: /* info_i */
        record->info_i = reg;
        break;
    }

    return 0;
}

int riscv_ras_do_inject(RiscvRasErrorRecord *record, RiscvRasStatus sts,
                        uint64_t addr, uint64_t info)
{
    RiscvRasStatus old;

    old = record->status_i;

    record->status_i.u64 = riscv_ras_write_status(old, sts);
    record->addr_i = addr;
    record->info_i = info;

    return 0;
}

int riscv_error_injection_tick(RiscvRasErrorRecord *record)
{
    int irq = 0;

        /* Check if the injection was cancelled. */
    if (record->control_i.eid == 0) {
        return RISCV_RAS_INJECT_ABORT;
    }
    if (--record->control_i.eid > 0) {
        return RISCV_RAS_INJECT_WAIT;
    }
    if (record->status_i.v == 1) {
        return RISCV_RAS_INJECT_ABORT;
    }

    record->status_i.v = 1;

    if (record->status_i.ue) {
        irq = record->control_i.uues;
    } else if (record->status_i.ce) {
        irq = record->control_i.ces;
    } else if (record->status_i.de) {
        irq = record->control_i.udes;
    }

    switch (irq) {
    case 1:
        return RISCV_RAS_INJECT_LOW;
    case 2:
        return RISCV_RAS_INJECT_HIGH;
    case 0:
    default:
        return RISCV_RAS_INJECT_ABORT;
    }
}

void riscv_ras_init(RiscvRasComponentRegisters *regs, uint16_t vendor_id, uint16_t imp_id)
{

    regs->vendor_n_imp_id.vendor_id = vendor_id;
    regs->vendor_n_imp_id.imp_id = imp_id;
    regs->component_id.inst_id = 0;
    regs->component_id.n_err_recs = RECORD_NUM;
    regs->component_id.version = 1;
}
