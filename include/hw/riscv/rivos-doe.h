/*
 * Rivos DOE Mailbox
 *
 * Copyright (C) 2022 Rivos Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef RIVOS_DOE_H
#define RIVOS_DOE_H

#include "qemu/osdep.h"
#include "exec/memory.h"
#include "hw/irq.h"

typedef struct RivosDOE RivosDOE;

/* Options */
#define DOE_CLIENT_INTERRUPT (1 << 0)
#define DOE_ASYNC_MESSAGES   (1 << 1)

RivosDOE *rivos_doe_create(Object *parent, uint32_t next_cap);
void rivos_doe_realize(RivosDOE *doe, AddressSpace *as);
void rivos_doe_reset(RivosDOE *doe);
MemoryRegion *rivos_doe_get_mr(RivosDOE *doe, bool host_regs);
qemu_irq *rivos_doe_get_host_irq(RivosDOE *doe);

MemTxResult rivos_doe_read(RivosDOE *doe, unsigned addr, uint32_t *val);
MemTxResult rivos_doe_write(RivosDOE *doe, unsigned addr, uint32_t val);

#endif
