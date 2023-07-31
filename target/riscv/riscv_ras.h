/*
 * RISC-V RAS (Reliability, Availability and Serviceability) block
 *
 * Copyright (c) 2023 Rivos Inc
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 or
 *  (at your option) any later version.
 */

#ifndef HW_MISC_RISCV_RAS_H
#define HW_MISC_RISCV_RAS_H

#include "qom/object.h"

#define TYPE_RISCV_RAS "riscv_ras"

DeviceState *riscv_ras_create(hwaddr);

int riscv_ras_inject(void *opaque, int record, hwaddr addr, uint64_t info);

#endif
