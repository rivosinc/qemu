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

#include "hw/riscv/rivos-doe.h"
#include "qemu/log.h"
#include "qemu/error-report.h"
#include "hw/registerfields.h"
#include "hw/sysbus.h"
#include "sysemu/dma.h"
#include "hw/pci/pcie_regs.h"

/* this should get into include/standard-headers/linux/pci_regs.h */
#define PCI_EXT_CAP_ID_DOE      0x2E    /* Data Object Exchange */

#define RIVOS_GENDOEMBOX_VERS   0x02

/*
 * The Rivos Generic DOE Mailbox spec:
 * https://docs.google.com/document/d/1jpLBILw3pgmHp-1nCq-00aeYWobQ9koYCJxIVDX4-vo/edit?usp=sharing
 * Snapshot of PCIe DOE Revision 1.1 ECR:
 * https://drive.google.com/file/d/1kWt1NkccDZonleNUjt9CwHgL2bTLkXO6/view
 *
 * Since Rivos systems have a number of DOE mailbox instances, in some
 * cases embedded with other functionality (e.g. the RoT widget), the
 * DOE mailbox implementation is expected to be instantiated as part of
 * another device and to have MMIO routed through that device.
 *
 * Since the initial focus of this model is on the Rivos Root-of-Trust
 * mailbox, some simplifications are mode (no client interrupt, no
 * PCIe capability registers).
 *
 * The optional Attention Mechanism feature is not supported.
 *
 * If interrupts are supported, the responder ("host") is responsible
 * for generating the MSI.
 *
 * TODO: support RACL checking for both register regions
 * TODO: flesh out abort, errors, etc.
 * TODO: PCIeExtCap, DoeCap registers - maybe?
 */

struct RivosDOE {
    MemoryRegion host_mmio;
    MemoryRegion client_mmio;

    AddressSpace *as;
    qemu_irq irq;

    uint32_t ext_cap;
    uint32_t cap;

    uint32_t ctrl;
    uint32_t status;

    uint32_t in_base;
    uint32_t in_max;
    uint32_t in_wrptr;

    uint32_t out_base;
    uint32_t out_max;
    uint32_t out_rdptr;

    uint32_t out_count;
};

REG32(DOE_EXT_CAP, 0x0)
REG32(DOE_CAP, 0x4)
    FIELD(DOE_CAP, INT,        0,  1)
    FIELD(DOE_CAP, INT_MSG,    1, 11)
    FIELD(DOE_CAP, ATTN,      12,  1)
    FIELD(DOE_CAP, ASYNC_MSG, 13,  1)
REG32(DOE_CTRL, 0x8)
    FIELD(DOE_CTRL, ABORT,     0, 1)
    FIELD(DOE_CTRL, INT_EN,    1, 1)
    FIELD(DOE_CTRL, ATTN,      2, 1)
    FIELD(DOE_CTRL, ASYNC_EN,  3, 1)
    FIELD(DOE_CTRL, GO,       31, 1)
REG32(DOE_STS, 0xc)
    FIELD(DOE_STS, BUSY,       0, 1)
    FIELD(DOE_STS, INT_STS,    1, 1)
    FIELD(DOE_STS, ERROR,      2, 1)
    FIELD(DOE_STS, ASYNC_STS,  3, 1)
    FIELD(DOE_STS, AT_ATTN,    4, 1)
    FIELD(DOE_STS, READY,     31, 1)
REG32(DOE_WDATA, 0x10)
REG32(DOE_RDATA, 0x14)

#define CLIENT_REGS_SIZE    0x18

REG32(HOST_TRUE_CTRL,     0x00)
    FIELD(TRUE_CTRL, INT_EN,    1, 1)
    FIELD(TRUE_CTRL, ASYNC_EN,  3, 1)
REG32(HOST_TRUE_STS,      0x04)
    FIELD(TRUE_STS, BUSY,       0, 1)
    FIELD(TRUE_STS, INT_STS,    1, 1)
    FIELD(TRUE_STS, ERROR,      2, 1)
    FIELD(TRUE_STS, ASYNC_STS,  3, 1)
    FIELD(TRUE_STS, AT_ATTN,    4, 1)
    FIELD(TRUE_STS, ABORT,     31, 1)     /* Host-only status bit */
REG32(HOST_IP_MBX_BASE,   0x08)
    FIELD(HOST_IP_MBX_BASE, VAL,  2, 30)
REG32(HOST_IP_MBX_LIMIT,  0x0C)
    FIELD(HOST_IP_MBX_LIMIT, VAL, 2, 30)
REG32(HOST_IP_MBX_WRPTR,  0x10)
REG32(HOST_OP_MBX_BASE,   0x14)
    FIELD(HOST_OP_MBX_BASE, VAL,  2, 30)
REG32(HOST_OP_MBX_LIMIT,  0x18)
    FIELD(HOST_OP_MBX_LIMIT, VAL, 2, 30)
REG32(HOST_OP_MBX_RDPTR,  0x1C)
REG32(HOST_OP_DW_CNT,     0x20)
    FIELD(HOST_OP_DW_CNT, CNT,    0, 10)

#define HOST_REGS_SIZE    0x24

static MemTxResult doe_host_read(void *opaque,
                                 hwaddr addr,
                                 uint64_t *val,
                                 unsigned size,
                                 MemTxAttrs attrs)
{
    RivosDOE *doe = opaque;
    uint32_t value;

    if ((size != 4) || (addr & 3)) {
        return MEMTX_ERROR;
    }

    switch (addr >> 2) {
    case R_HOST_TRUE_CTRL:
        value = doe->ctrl;
        break;
    case R_HOST_TRUE_STS:
        value = doe->status;
        break;
    case R_HOST_IP_MBX_BASE:
        value = doe->in_base;
        break;
    case R_HOST_IP_MBX_LIMIT:
        value = doe->in_max;
        break;
    case R_HOST_IP_MBX_WRPTR:
        value = doe->in_wrptr;
        break;
    case R_HOST_OP_MBX_BASE:
        value = doe->out_base;
        break;
    case R_HOST_OP_MBX_LIMIT:
        value = doe->out_max;
        break;
    case R_HOST_OP_MBX_RDPTR:
        value = doe->out_rdptr;
        break;
    case R_HOST_OP_DW_CNT:
        value = doe->out_count;
        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: Bad offset 0x%"HWADDR_PRIx"\n", __func__, addr);
        return MEMTX_DECODE_ERROR;
    }

    //printf("DOE host read +%x -> %08x\n", (int)addr, value);
    *val = value;
    return MEMTX_OK;
}

static MemTxResult doe_host_write(void *opaque,
                                  hwaddr addr,
                                  uint64_t val64,
                                  unsigned size,
                                  MemTxAttrs attrs)
{
    RivosDOE *doe = opaque;
    uint32_t val = val64;

    if ((size != 4) || (addr & 3)) {
        return MEMTX_ERROR;
    }

    /*
     * FIXME: open questions in the spec regarding:
     * - alignment of IP_MBX_WRPTR and OP_MBX_RDPTR
     * - hw prevention of sw updates to certain registers will OP_DW_CNT != 0
     * - hw enforcement of base/limit/ptr values written by sw
     */

    //printf("DOE host write +%x -> %08x\n", (int)addr, val);
    switch (addr >> 2) {
    case R_HOST_TRUE_CTRL:
        doe->ctrl = val & (R_TRUE_CTRL_INT_EN_MASK|R_TRUE_CTRL_ASYNC_EN_MASK);
        break;
    case R_HOST_TRUE_STS:
        doe->status = val & (R_TRUE_STS_ABORT_MASK|R_TRUE_STS_ASYNC_STS_MASK|
                             R_TRUE_STS_BUSY_MASK|R_TRUE_STS_ERROR_MASK|
                             R_TRUE_STS_INT_STS_MASK);
        /* FIXME: this is a guess; the spec needs to clarify deassertion condition */
        if (!(doe->status & (R_TRUE_STS_ABORT_MASK|R_TRUE_STS_BUSY_MASK))) {
            qemu_irq_lower(doe->irq);
        }
        break;
    case R_HOST_IP_MBX_BASE:
        doe->in_base = val & R_HOST_IP_MBX_BASE_VAL_MASK;
        break;
    case R_HOST_IP_MBX_LIMIT:
        doe->in_max = val & R_HOST_IP_MBX_LIMIT_VAL_MASK;
        break;
    case R_HOST_IP_MBX_WRPTR:
        doe->in_wrptr = val;
        break;
    case R_HOST_OP_MBX_BASE:
        doe->out_base = val & R_HOST_OP_MBX_BASE_VAL_MASK;
        break;
    case R_HOST_OP_MBX_LIMIT:
        doe->out_max = val & R_HOST_OP_MBX_LIMIT_VAL_MASK;
        break;
    case R_HOST_OP_MBX_RDPTR:
        doe->out_rdptr = val;
        break;
    case R_HOST_OP_DW_CNT:
        doe->out_count = val & R_HOST_OP_DW_CNT_CNT_MASK;
        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: Bad offset 0x%"HWADDR_PRIx"\n", __func__, addr);
        return MEMTX_DECODE_ERROR;
    }

    return MEMTX_OK;
}

static const MemoryRegionOps doe_host_ops = {
    .read_with_attrs = doe_host_read,
    .write_with_attrs = doe_host_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

static MemTxResult doe_client_read(void *opaque,
                                   hwaddr addr,
                                   uint64_t *val,
                                   unsigned size,
                                   MemTxAttrs attrs)
{
    RivosDOE *doe = opaque;
    uint32_t value = 0;

    switch (addr >> 2) {
    case R_DOE_EXT_CAP:
        value = doe->ext_cap;
        break;
    case R_DOE_CAP:
        value = doe->cap;
        break;
    case R_DOE_CTRL:
        value = doe->ctrl;
        break;
    case R_DOE_STS:
        value = doe->status & ~R_TRUE_STS_ABORT_MASK;
        if (doe->out_count > 0) {
            value |= R_DOE_STS_READY_MASK;
        }
        break;
    case R_DOE_WDATA:
        break;
    case R_DOE_RDATA: {
        if (doe->out_count > 0) {
            /* TODO: handle errors when the behavior is spec'd. */
            dma_memory_read(doe->as, doe->out_rdptr, &value, 4,
                            MEMTXATTRS_UNSPECIFIED);
        }
        break;
    }
    default:
        return MEMTX_DECODE_ERROR;
    }

    //printf("DOE client read +%x -> %08x\n", (int)addr, value);
    *val = value;
    return MEMTX_OK;
}

static MemTxResult doe_client_write(void *opaque,
                                   hwaddr addr,
                                   uint64_t val64,
                                   unsigned size,
                                   MemTxAttrs attrs)
{
    RivosDOE *doe = opaque;
    uint32_t val = val64;

    //printf("DOE client write +%x -> %08x\n", (int)addr, val);
    switch (addr >> 2) {
    case R_DOE_EXT_CAP:
    case R_DOE_CAP:
        break;
    case R_DOE_CTRL:
        if (val & R_DOE_CTRL_ABORT_MASK) {
            doe->in_wrptr = doe->in_base;
            if ((doe->status & R_TRUE_STS_BUSY_MASK) ||
                (doe->status & R_TRUE_STS_ERROR_MASK) ||
                (doe->out_count > 0)) {
                /* Let the host process the abort */
                doe->status |= R_TRUE_STS_ABORT_MASK;
                qemu_irq_raise(doe->irq);
            }
        } else if ((val & R_DOE_CTRL_GO_MASK) &&
                    !(doe->status & (R_TRUE_STS_ABORT_MASK |
                                     R_TRUE_STS_BUSY_MASK |
                                     R_TRUE_STS_ERROR_MASK))) {
            doe->status |= R_TRUE_STS_BUSY_MASK;
            qemu_irq_raise(doe->irq);
        }
        doe->ctrl |= val & R_DOE_CTRL_INT_EN_MASK;
        doe->ctrl |= val & R_DOE_CTRL_ASYNC_EN_MASK;
        break;
    case R_DOE_STS:
        if (val & R_DOE_STS_INT_STS_MASK) {
            doe->status &= ~R_DOE_STS_INT_STS_MASK;
        }
        if (val & R_DOE_STS_ASYNC_STS_MASK) {
            doe->status &= ~R_DOE_STS_ASYNC_STS_MASK;
        }
        break;
    case R_DOE_WDATA:
        if (!(doe->status & R_DOE_STS_BUSY_MASK) &&
             (doe->in_wrptr < doe->in_max)) {
            /* TODO: handle errors when the behavior is spec'd. */
            dma_memory_write(doe->as, doe->in_wrptr, &val, 4,
                             MEMTXATTRS_UNSPECIFIED);
            doe->in_wrptr += 4;
        }
        break;
    case R_DOE_RDATA:
        if (doe->out_count > 0) {
            doe->out_rdptr += 4;
            doe->out_count--;
        }
        break;
    default:
        return MEMTX_DECODE_ERROR;
    }

    return MEMTX_OK;
}

static const MemoryRegionOps doe_client_ops = {
    .read_with_attrs = doe_client_read,
    .write_with_attrs = doe_client_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

/*
 * The embedding device will wire up the register regions as
 * appropriate, so make them available.
 */
MemoryRegion *rivos_doe_get_mr(RivosDOE *doe, bool host_regs)
{
    return host_regs ? &doe->host_mmio : &doe->client_mmio;
}

/*
 * Let the embedding device init the IRQ, but because it needs to
 * have a pointer to our private storage of the qemu_irq.
 */
qemu_irq *rivos_doe_get_host_irq(RivosDOE *doe)
{
    return &doe->irq;
}

/*
 * The embedding device passes in the AddressSpace and that should be
 * used for DOE message transfer.
 */
void rivos_doe_realize(RivosDOE *doe, AddressSpace *as)
{
    doe->as = as;
}

void rivos_doe_reset(RivosDOE *doe)
{
    /* Host firmware is responsible for most state clearing */
}

RivosDOE *rivos_doe_create(Object *parent, uint32_t next_cap)
{
    RivosDOE *doe = g_new0(RivosDOE, 1);

    /*
     * TODO: instances within PCIe config headers may require some
     * refactoring overall to interface play nice with PCIDevice.
     */
    doe->ext_cap = PCI_EXT_CAP(PCI_EXT_CAP_ID_DOE,
                               RIVOS_GENDOEMBOX_VERS,
                               next_cap);

    /* All features are always present even if non-functional or unused */
    doe->cap = R_DOE_CAP_ASYNC_MSG_MASK | R_DOE_CAP_INT_MASK;

    memory_region_init_io(&doe->host_mmio, parent, &doe_host_ops,
                          doe, "doe-host", HOST_REGS_SIZE);
    memory_region_init_io(&doe->client_mmio, parent, &doe_client_ops,
                          doe, "doe-client", CLIENT_REGS_SIZE);

    return doe;
}
