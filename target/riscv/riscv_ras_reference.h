/*
 * RISC-V RAS (Reliability, Availability and Serviceability) block
 *
 * Copyright (c) 2023 Rivos Inc
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 or
 *  (at your option) any later version.
 */

#ifndef HW_MISC_RISCV_RAS_REFERENCE_H
#define HW_MISC_RISCV_RAS_REFERENCE_H

#include "riscv_ras_regs.h"

enum {
    RISCV_RAS_INJECT_WAIT,  /* Wait one tick and try again. */
    RISCV_RAS_INJECT_ABORT, /* Abort the injection. */
    RISCV_RAS_INJECT_HIGH,  /* Fire a low priority interrupt. */
    RISCV_RAS_INJECT_LOW    /* Fire a high priority interrupt. */
};

/**
 * @brief Validate and commit a write transaction. Caller is responsible for
 * serializing all accesses to the RAS registers.
 *
 * @param page[in] - Pointer to the RAS registers
 * @param addr[in] - Offset of the register in bytes
 * @param val[in] - Value to write
 * @param size[in] - Size of the write transaction
 * @param inject[out] - Output flag set to true if the injection logic
 * is to be triggered
 *
 * @return 0 on success, error code otherwise
 */
int riscv_ras_write(RiscvRasComponentRegisters *regs, uintptr_t addr, uint64_t val,
                        unsigned size, bool *inject, bool *clrsts);
/**
 * @brief Read a RAS register. Caller is responsible for serializing all
 * accesses to the RAS registers.
 *
 * @param page[in] - Pointer to the RAS registers
 * @param addr[in] - Offset of the register in bytes
 * @param out[out] - Where to return the data to
 * @param size[in] - Size of the read transaction
 *
 * @return 0 on success, error code otherwise
 */
int riscv_ras_read(RiscvRasComponentRegisters *regs, uintptr_t addr, uint64_t *out,
                        unsigned size);

/**
 * @brief Initialize RAS emulation, set all registers to their default values.
 * Fill in the provided vendor information.
 *
 * @param page[in] - Pointer to the RAS registers
 * @param vendor_id[in] - JEDEC manufacturer id
 * @param imp_id[in] - Unique identity of the component
 */
void riscv_ras_init(RiscvRasComponentRegisters *regs, uint16_t vendor_id, uint16_t imp_id);
/**
 * @brief Inject a data corruption error
 *
 * @param record[in] - Pointer to a RAS error record registers
 * @param sts[in] - Status register describing the error
 * @param addr[in] - Address of the fault
 * @param info[in] - Additional, vendor specific information
 *
 * @return 0 on success, error code otherwise
 */
int riscv_ras_do_inject(RiscvRasErrorRecord *record, RiscvRasStatus sts,
                        uint64_t addr, uint64_t info);

/**
 * @brief Do one tick of the error injection logic
 *
 * @param record[in] - Pointer to a RAS error record registers
 *
 * @return One of RISCV_RAS_INJECT_WAIT, RISCV_RAS_INJECT_ABORT,
 * RISCV_RAS_INJECT_HIGH, RISCV_RAS_INJECT_LOW
 */
int riscv_error_injection_tick(RiscvRasErrorRecord *record);

#endif
