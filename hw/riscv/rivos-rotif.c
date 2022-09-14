/*
 * Rivos Root-of-Trust "widget" including DOE
 *
 * Copyright (C) 2022 Rivos Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "hw/riscv/rivos-rotif.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "hw/sysbus.h"
#include "hw/riscv/rivos-doe.h"
#include "migration/vmstate.h"
#include "exec/address-spaces.h"
#include "hw/qdev-properties.h"
#include "hw/qdev-properties-system.h"
#include "hw/registerfields.h"
#include "hw/irq.h"

#define ROTIF_DOE_OFFSET    0x028
#define ROTIF_RLRAM_OFFSET  0x400
#define ROTIF_RLRAM_SIZE    0x400

#define ROTIF_COUNT_MAX     1024

#define ROTIF_NUM_COUNTERS        8
#define ROTIF_NUM_SEMAPHORES      2
#define ROTIF_NUM_SCRATCH         9
#define ROTIF_NUM_RAM_BYTES       1024

REG32(COUNTER0, 0x00)
REG32(COUNTER1, 0x04)
REG32(COUNTER2, 0x08)
REG32(COUNTER3, 0x0C)
REG32(COUNTER4, 0x10)
REG32(COUNTER5, 0x14)
REG32(COUNTER6, 0x18)
REG32(COUNTER7, 0x1C)

REG32(SEM0, 0x20)
REG32(SEM1, 0x24)

REG32(SCRATCH0, 0x38)
REG32(SCRATCH1, 0x40)
REG32(SCRATCH2, 0x48)
REG32(SCRATCH3, 0x50)
REG32(SCRATCH4, 0x58)
REG32(SCRATCH5, 0x60)
REG32(SCRATCH6, 0x68)
REG32(SCRATCH7, 0x70)
REG32(SCRATCH8, 0x78)

/* RLRAM is implemented within MMIO to allow RACL enforcement */
REG32(RLRAM_START, ROTIF_RLRAM_OFFSET)
REG32(RLRAM_END,   ROTIF_RLRAM_OFFSET+ROTIF_RLRAM_SIZE-4)

struct RivosRotIFState {
    /* <private> */
    SysBusDevice parent_obj;

    /* <public> */
    MemoryRegion regs;
    MemoryRegion *dma_mr;
    AddressSpace dma_as;
    qemu_irq doe_host_irq;

    uint32_t counter[ROTIF_NUM_COUNTERS];
    uint32_t sem[ROTIF_NUM_SEMAPHORES];
    uint8_t  scratch[ROTIF_NUM_SCRATCH * 8];
    uint8_t  rlram[ROTIF_NUM_RAM_BYTES];

    hwaddr cur_addr;
    uint32_t bytes_left;

    int32_t role_check;

    /* Host state */
    RivosDOE *rdoe;
};

static MemTxResult rotif_read(void *opaque,
                              hwaddr addr,
                              uint64_t *val,
                              unsigned size,
                              MemTxAttrs attrs)
{
    RivosRotIFState *s = opaque;
    unsigned reg = (unsigned)(addr >> 2);
    unsigned offset;
    uint64_t value = 0;

    if (s->role_check != -1 && (attrs.requester_id != s->role_check)) {
        *val = 0;
        qemu_log_mask(LOG_GUEST_ERROR, "[ROTIF] read access denied, role %u\n",
            attrs.requester_id);
        return MEMTX_OK;
    }

    if (addr & (size - 1)) {
        *val = 0;
        return MEMTX_OK;
    }

    switch (reg) {
    case R_COUNTER0...R_COUNTER7:
        if (size == 4) {
            value = s->counter[reg - R_COUNTER0];
        }
        break;
    case R_SEM0...R_SEM1:
        if (size == 4) {
            value = s->sem[reg - R_SEM0];
        }
        break;
    case R_SCRATCH0...R_SCRATCH8+1:
        offset = addr - A_SCRATCH0;
        if (size == 1) {
            value = s->scratch[offset];
        } else if (size == 2) {
            value = lduw_le_p(&s->scratch[offset]);
        } else if (size == 4) {
            value = ldl_le_p(&s->scratch[offset]);
        } else if (size == 8) {
            value = ldq_le_p(&s->scratch[offset]);
        }
        break;
    case R_RLRAM_START...R_RLRAM_END:
        offset = addr - A_RLRAM_START;
        if (size == 4) {
            value = ldl_le_p(&s->rlram[offset]);
        } else if (size == 8) {
            value = ldq_le_p(&s->rlram[offset]);
        }
        break;
    }

    //printf("  [ROTIF] read  +0x%02x/%u > %08lx\n", (unsigned)addr, size, value);
    *val = value;
    return MEMTX_OK;
}

static MemTxResult rotif_write(void *opaque,
                               hwaddr addr,
                               uint64_t val,
                               unsigned size,
                               MemTxAttrs attrs)
{
    RivosRotIFState *s = opaque;
    unsigned reg = (unsigned)(addr >> 2);
    unsigned offset;

    if (s->role_check != -1 && (attrs.requester_id != s->role_check)) {
        qemu_log_mask(LOG_GUEST_ERROR, "[ROTIF] write access denied, role %u\n",
            attrs.requester_id);
        return MEMTX_OK;
    }

    if (addr & (size - 1)) {
        return MEMTX_OK;
    }

    //printf("  [ROTIF] write +0x%02x/%u < %08lx\n", (unsigned)addr, size, val);
    switch (reg) {
    case R_COUNTER0...R_COUNTER7:
        if (size == 4) {
            unsigned counter = reg - R_COUNTER0;
            if (val == 0) {
                s->counter[counter] = 0;
            } else if ((uint32_t)val == 0xffffffff) {
                if (s->counter[counter] > 0) {
                    s->counter[counter]--;
                }
            } else if (val == 1) {
                if (s->counter[counter] < ROTIF_COUNT_MAX) {
                    s->counter[counter]++;
                }
            }
        }
        break;
    case R_SEM0...R_SEM1:
        if (size == 4) {
            unsigned sem = reg - R_SEM0;
            if (val == 0) {
                s->sem[sem] = 0;
            } else if (s->sem[sem] == 0) {
                s->sem[sem] = val;
            }
        }
        break;
    case R_SCRATCH0...R_SCRATCH8+1:
        offset = addr - A_SCRATCH0;
        if (size == 1) {
            s->scratch[offset] = val;
        } else if (size == 2) {
            stw_le_p(&s->scratch[offset], val);
        } else if (size == 4) {
            stl_le_p(&s->scratch[offset], val);
        } else if (size == 8) {
            stq_le_p(&s->scratch[offset], val);
        }
        break;
    case R_RLRAM_START...R_RLRAM_END:
        offset = addr - A_RLRAM_START;
        if (size == 4) {
            stl_le_p(&s->rlram[offset], val);
        } else if (size == 8) {
            stq_le_p(&s->rlram[offset], val);
        }
        break;
    }

    return MEMTX_OK;
}

static const MemoryRegionOps rotif_ops = {
    .read_with_attrs = rotif_read,
    .write_with_attrs = rotif_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .impl = {
        .min_access_size = 1,
        .max_access_size = 8,
    },
};

static const VMStateDescription vmstate_rivos_rotif = {
    .name = TYPE_RIVOS_ROTIF,
    .unmigratable = 1
};

static Property rivos_rotif_properties[] = {
    DEFINE_PROP_INT32("role", RivosRotIFState, role_check, -1),
    DEFINE_PROP_LINK("dma-mr", RivosRotIFState, dma_mr,
        TYPE_MEMORY_REGION, MemoryRegion *),
    DEFINE_PROP_END_OF_LIST(),
};

static void rivos_rotif_reset(DeviceState *dev)
{
    RivosRotIFState *s = RIVOS_ROTIF(dev);

    rivos_doe_reset(s->rdoe);
}

static void rivos_rotif_init(Object *obj)
{
    RivosRotIFState *s = RIVOS_ROTIF(obj);

    s->rdoe = rivos_doe_create(obj, 0);
}

static void rivos_rotif_realize(DeviceState *dev, Error **errp)
{
    RivosRotIFState *s = RIVOS_ROTIF(dev);
    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);

    /*
     * The DOE device copies messages to and from an SRAM, targeting
     * either a machine-provided root MemoryRegion, or defaulting to
     * system memory. An AddressSpace is created and passed to the
     * DOE model.
     */
    if (!s->dma_mr) {
        s->dma_mr = get_system_memory();
    }
    address_space_init(&s->dma_as, s->dma_mr, "rotif-doe");
    rivos_doe_realize(s->rdoe, &s->dma_as);

    /*
     * The register page includes the widget registers, the RLRAM, and
     * the client side of the DOE module.
     */
    memory_region_init_io(&s->regs, OBJECT(dev), &rotif_ops, s,
                          "rotif", 0x1000);
    memory_region_add_subregion(&s->regs, ROTIF_DOE_OFFSET,
                                rivos_doe_get_mr(s->rdoe, false));

    /* DOE host IRQ is the only one for the machine to wire up */
    sysbus_init_irq(sbd, rivos_doe_get_host_irq(s->rdoe));

    /* Main (client) registers first, then the DOE host */
    sysbus_init_mmio(sbd, &s->regs);
    sysbus_init_mmio(sbd, rivos_doe_get_mr(s->rdoe, true));
}

static void rivos_rotif_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->reset = rivos_rotif_reset;
    dc->realize = rivos_rotif_realize;
    dc->vmsd = &vmstate_rivos_rotif;
    device_class_set_props(dc, rivos_rotif_properties);
}

static const TypeInfo rivos_rotif_info = {
    .name          = TYPE_RIVOS_ROTIF,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(RivosRotIFState),
    .instance_init = rivos_rotif_init,
    .class_init    = rivos_rotif_class_init,
};

static void rivos_rotif_register_types(void)
{
    type_register_static(&rivos_rotif_info);
}

type_init(rivos_rotif_register_types)
