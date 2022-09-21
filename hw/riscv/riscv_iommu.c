/*
 * QEMU emulation of an RISC-V IOMMU (Ziommu)
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

#include "qemu/osdep.h"
#include "qom/object.h"
#include "hw/pci/pci_bus.h"
#include "hw/pci/msi.h"
#include "hw/pci/msix.h"
#include "hw/qdev-properties.h"
#include "hw/riscv/riscv_hart.h"
#include "hw/riscv/riscv_iommu.h"
#include "migration/vmstate.h"
#include "qapi/error.h"
#include "qemu/error-report.h"

#include "trace.h"

#ifndef PCI_VENDOR_ID_RIVOS
#define PCI_VENDOR_ID_RIVOS           0x1efd
#endif

#ifndef PCI_DEVICE_ID_RIVOS_IOMMU
#define PCI_DEVICE_ID_RIVOS_IOMMU     0xedf1
#endif

/* Physical page number coversions */
#define PPN_PHYS(ppn)                 ((ppn) << TARGET_PAGE_BITS)
#define PPN_DOWN(phy)                 ((phy) >> TARGET_PAGE_BITS)

typedef struct RISCVIOMMUContext RISCVIOMMUContext;
typedef struct RISCVIOMMUState   RISCVIOMMUState;

struct RISCVIOMMUState {
    uint32_t devid;       /* requester Id, 0 if not assigned. */
    uint32_t version;     /* Reported interface version number */

    uint64_t cap;         /* IOMMU supported capabitilites */

    bool enable_off;      /* Enable out-of-reset OFF mode (DMA disabled) */
    bool enable_ats;      /* Enable ATS support */
    bool enable_s_stage;  /* Enable S/VS-Stage translation */
    bool enable_g_stage;  /* Enable G-Stage translation */

    uint64_t ddtp;        /* Validated Device Directory Tree Root Pointer */
    dma_addr_t cq_addr;   /* Command queue base physical address */
    uint32_t cq_mask;     /* Command queue index bitmask */
    dma_addr_t fq_addr;   /* Fault/event queue base physical address */
    uint32_t fq_mask;     /* Fault/event queue index bitmask */
    dma_addr_t pq_addr;   /* Page request queue base physical address */
    uint32_t pq_mask;     /* Page request queue index bitmask */

    QemuThread core_proc; /* Background processing thread */
    QemuCond core_cond;   /* Background processing wakeup signal */
    QemuMutex core_lock;  /* Global IOMMU lock, used for cache/regs updates */
    unsigned core_exec;   /* Processing thread execution actions */

    AddressSpace *target_as;        /* IOMMU target address space */
    MemoryRegion *down_mr;

    /* interrupt delivery callback */
    void (*notify)(RISCVIOMMUState *iommu, unsigned vector);

    MemoryRegion regs_mr;           /* MMIO interface */
    QemuSpin regs_lock;             /* MMIO register lock */

    uint8_t regs_rw[RIO_REG_SIZE];  /* MMIO register state (user write) */
    uint8_t regs_wc[RIO_REG_SIZE];  /* MMIO write-1-to-clear mask */
    uint8_t regs_ro[RIO_REG_SIZE];  /* MMIO read/only mask */

    QLIST_ENTRY(RISCVIOMMUState) iommus;
    QLIST_HEAD(, RISCVIOMMUSpace) spaces;
};

/* Device assigned I/O address space */
struct RISCVIOMMUSpace {
    IOMMUMemoryRegion iova_mr;  /* IOVA memory region for attached device */
    AddressSpace iova_as;       /* IOVA address space for attached device */
    RISCVIOMMUState *iommu;     /* Managing IOMMU device state */
    uint32_t devid;             /* Requester identifier, AKA device_id */
    QLIST_ENTRY(RISCVIOMMUSpace) list;
};

/* ctx_cache elements, translation context state. */
struct RISCVIOMMUContext {
    uint64_t devid:24;          /* Requester Id, AKA device_id */
    uint64_t __rfu:40;          /* reserved */
    uint64_t tc;                /* Translation Control */
    uint64_t ta;                /* Translation Attributes */
    uint64_t satp;              /* S-Stage address translation and protection */
    uint64_t gatp;              /* G-Stage address translation and protection */
};

/* Register helper functions */
static uint32_t riscv_iommu_reg_mod32(RISCVIOMMUState *s, unsigned idx,
    uint32_t set, uint32_t clr)
{
    uint8_t *ptr = &s->regs_rw[idx];
    uint32_t val;
    qemu_spin_lock(&s->regs_lock);
    val = ldl_le_p(ptr);
    stl_le_p(ptr, (val & ~clr) | set);
    qemu_spin_unlock(&s->regs_lock);
    return val;
}

static void riscv_iommu_reg_set32(RISCVIOMMUState *s, unsigned idx,
    uint32_t set)
{
    uint8_t *ptr = &s->regs_rw[idx];
    qemu_spin_lock(&s->regs_lock);
    stl_le_p(ptr, set);
    qemu_spin_unlock(&s->regs_lock);
}

static uint32_t riscv_iommu_reg_get32(RISCVIOMMUState *s, unsigned idx)
{
    uint8_t *ptr = &s->regs_rw[idx];
    return ldl_le_p(ptr);
}

static uint64_t riscv_iommu_reg_mod64(RISCVIOMMUState *s,
    unsigned idx, uint64_t set, uint64_t clr)
{
    uint8_t *ptr = &s->regs_rw[idx];
    uint64_t val;
    qemu_spin_lock(&s->regs_lock);
    val = ldq_le_p(ptr);
    stq_le_p(ptr, (val & ~clr) | set);
    qemu_spin_unlock(&s->regs_lock);
    return val;
}

static void riscv_iommu_reg_set64(RISCVIOMMUState *s, unsigned idx,
    uint64_t set)
{
    uint8_t *ptr = &s->regs_rw[idx];
    qemu_spin_lock(&s->regs_lock);
    stq_le_p(ptr, set);
    qemu_spin_unlock(&s->regs_lock);
}

static uint64_t riscv_iommu_reg_get64(RISCVIOMMUState *s, unsigned idx)
{
    uint8_t *ptr = &s->regs_rw[idx];
    return ldq_le_p(ptr);
}

static void riscv_iommu_irq_assert(RISCVIOMMUState *s, int vec)
{
    const uint32_t ipsr = riscv_iommu_reg_mod32(s, RIO_REG_IPSR, (1 << vec), 0);
    const uint32_t ivec = riscv_iommu_reg_get32(s, RIO_REG_IVEC);
    if (s->notify && !(ipsr & (1 << vec))) {
        s->notify(s, (ivec >> (vec * 4)) & 0x0F);
    }
}

static void riscv_iommu_fault(RISCVIOMMUState *s, RISCVIOMMUEvent *ev)
{
    uint32_t ctrl = riscv_iommu_reg_get32(s, RIO_REG_FQCSR);
    uint32_t head = riscv_iommu_reg_get32(s, RIO_REG_FQH) & s->fq_mask;
    uint32_t tail = riscv_iommu_reg_get32(s, RIO_REG_FQT) & s->fq_mask;
    uint32_t next = (tail + 1) & s->fq_mask;
    uint32_t devid = ev->reason & ((1U << 20) - 1);

    trace_riscv_iommu_flt(PCI_BUS_NUM(devid), PCI_SLOT(devid),
                          PCI_FUNC(devid), ev->reason, ev->iova);

    if (!(ctrl & RIO_FQ_ACTIVE) || !!(ctrl & (RIO_FQ_FULL | RIO_FQ_FAULT))) {
        return;
    }

    if (head == next) {
        riscv_iommu_reg_mod32(s, RIO_REG_CQCSR, RIO_FQ_FULL, 0);
    } else {
        dma_addr_t addr = s->fq_addr + tail * sizeof(RISCVIOMMUEvent);
        if (dma_memory_write(s->target_as, addr, ev, sizeof(*ev),
                             MEMTXATTRS_UNSPECIFIED) != MEMTX_OK) {
            riscv_iommu_reg_mod32(s, RIO_REG_CQCSR, RIO_FQ_FAULT, 0);
        } else {
            riscv_iommu_reg_set32(s, RIO_REG_FQT, next);
        }
    }

    if (ctrl & RIO_FQ_IE) {
        riscv_iommu_irq_assert(s, RIO_INT_FQ);
    }
}

/*
 * RISCV IOMMU Address Translation Lookup - Page Table Walk
 *
 * Note: Code is based on get_physical_address() from target/riscv/cpu_helper.c
 * Both implementation can be merged into single helper function in future.
 * Keeping them separate for now, as error reporting and flow specifics are
 * sufficiently different for separate implementation.
 *
 * @s        : IOMMU Device State
 * @ctx      : Translation context for device id and process address space id.
 * @iotlb    : translation data: physical address and access mode.
 * @gpa      : provided IOVA is a guest physical address, use G-Stage only.
 * @return   : success or fault cause code.
 */
static int riscv_iommu_spa_fetch(RISCVIOMMUState *s, RISCVIOMMUContext *ctx,
        IOMMUTLBEntry *iotlb, bool gpa)
{
    dma_addr_t addr, base;
    uint64_t satp, gatp, pte;
    bool pass, en_s, en_g;
    struct {
        unsigned char step;
        unsigned char levels;
        unsigned char ptidxbits;
        unsigned char ptesize;
    } sc[2];

    satp = get_field(ctx->satp, RIO_ATP_MASK_MODE);
    gatp = get_field(ctx->gatp, RIO_ATP_MASK_MODE);

    en_s = satp != RIO_ATP_MODE_BARE && !gpa;
    en_g = gatp != RIO_ATP_MODE_BARE;

    /* Exit early for pass-through mode. */
    if (!(en_s || en_g)) {
        iotlb->translated_addr = iotlb->iova;
        iotlb->addr_mask = ~TARGET_PAGE_MASK;
        /* No permission checks in pass-through mode */
        iotlb->perm = IOMMU_RW;
        return 0;
    }

    /* S/G translation parameters. */
    pass = true;
    do {
        sc[pass].step = 0;
        switch (pass ? gatp : satp) {
        case RIO_ATP_MODE_BARE:
            sc[pass].levels    = 0;
            sc[pass].ptidxbits = 0;
            sc[pass].ptesize   = 0;
            break;
        case RIO_ATP_MODE_SV32:
            if (!(s->cap & (pass ? RIO_CAP_G_SV32 : RIO_CAP_G_SV32))) {
                return RIO_CAUSE_DDT_UNSUPPORTED;
            }
            sc[pass].levels    = 2;
            sc[pass].ptidxbits = 10;
            sc[pass].ptesize   = 4;
            break;
        case RIO_ATP_MODE_SV39:
            if (!(s->cap & (pass ? RIO_CAP_G_SV39 : RIO_CAP_G_SV39))) {
                return RIO_CAUSE_DDT_UNSUPPORTED;
            }
            sc[pass].levels    = 3;
            sc[pass].ptidxbits = 9;
            sc[pass].ptesize   = 8;
            break;
        case RIO_ATP_MODE_SV48:
            if (!(s->cap & (pass ? RIO_CAP_G_SV48 : RIO_CAP_G_SV48))) {
                return RIO_CAUSE_DDT_UNSUPPORTED;
            }
            sc[pass].levels    = 4;
            sc[pass].ptidxbits = 9;
            sc[pass].ptesize   = 8;
            break;
        case RIO_ATP_MODE_SV57:
            if (!(s->cap & (pass ? RIO_CAP_G_SV57 : RIO_CAP_G_SV57))) {
                return RIO_CAUSE_DDT_UNSUPPORTED;
            }
            sc[pass].levels    = 5;
            sc[pass].ptidxbits = 9;
            sc[pass].ptesize   = 8;
            break;
        default:
            return RIO_CAUSE_DDT_UNSUPPORTED;
        }
        pass = !pass;
    } while (!pass);

    /* S/G stages translation tables root pointers */
    gatp = PPN_PHYS(get_field(ctx->gatp, RIO_ATP_MASK_PPN));
    satp = PPN_PHYS(get_field(ctx->satp, RIO_ATP_MASK_PPN));
    addr = (en_s && en_g) ? satp : iotlb->iova;
    base = en_g ? gatp : satp;
    pass = en_g;

    do {
        const unsigned widened = (pass && !sc[pass].step) ? 2 : 0;
        const unsigned va_bits = widened + sc[pass].ptidxbits;
        const unsigned va_skip = TARGET_PAGE_BITS + sc[pass].ptidxbits *
                                 (sc[pass].levels - 1 - sc[pass].step);
        const unsigned idx = (addr >> va_skip) & ((1 << va_bits) - 1);
        const dma_addr_t pte_addr = base + idx * sc[pass].ptesize;

        /* Address range check before first level lookup */
        if (!sc[pass].step) {
            const uint64_t va_mask = (1ULL << (va_skip + va_bits)) - 1;
            if ((addr & va_mask) != addr) {
                return RIO_CAUSE_DMA_DISABLED;
            }
        }

        /* Read page table entry */
        if (dma_memory_read(s->target_as, pte_addr, &pte,
                sc[pass].ptesize, MEMTXATTRS_UNSPECIFIED) != MEMTX_OK) {
            return (iotlb->perm & IOMMU_WO) ? RIO_CAUSE_WR_FAULT
                                            : RIO_CAUSE_RD_FAULT;
        }

        if (sc[pass].ptesize == 4) {
            pte = (uint64_t) le32_to_cpu(*((uint32_t *)&pte));
        } else {
            pte = le64_to_cpu(pte);
        }

        sc[pass].step++;
        hwaddr ppn = pte >> PTE_PPN_SHIFT;

        if (!(pte & PTE_V)) {
            break;                /* Invalid PTE */
        } else if (!(pte & (PTE_R | PTE_W | PTE_X))) {
            base = PPN_PHYS(ppn); /* Inner PTE, continue walking */
        } else if ((pte & (PTE_R | PTE_W | PTE_X)) == PTE_W) {
            break;                /* Reserved leaf PTE flags: PTE_W */
        } else if ((pte & (PTE_R | PTE_W | PTE_X)) == (PTE_W | PTE_X)) {
            break;                /* Reserved leaf PTE flags: PTE_W + PTE_X */
        } else if (ppn & ((1ULL << (va_skip - TARGET_PAGE_BITS)) - 1)) {
            break;                /* Misaligned PPN */
        } else if ((iotlb->perm & IOMMU_RO) && !(pte & PTE_R)) {
            break;                /* Read access check failed */
        } else if ((iotlb->perm & IOMMU_WO) && !(pte & PTE_W)) {
            break;                /* Write access check failed */
        } else {
            /* Leaf PTE, translation completed. */
            sc[pass].step = sc[pass].levels;
            base = PPN_PHYS(ppn) | (addr & ((1ULL << va_skip) - 1));
            /* Update address mask based on smallest translation granularity */
            iotlb->addr_mask &= (1ULL << va_skip) - 1;
            /* Continue with S-Stage translation? */
            if (pass && sc[0].step != sc[0].levels) {
                pass = false;
                addr = iotlb->iova;
                continue;
            }
            /* Translation phase completed (GPA or SPA) */
            iotlb->translated_addr = base;
            iotlb->perm = (pte & PTE_W) ? ((pte & PTE_R) ? IOMMU_RW : IOMMU_WO)
                                                         : IOMMU_RO;
            /* Continue with G-Stage translation? */
            if (!pass && en_g) {
                pass = true;
                addr = base;
                base = gatp;
                sc[pass].step = 0;
                continue;
            }
            return 0;
        }

        if (sc[pass].step == sc[pass].levels) {
            break; /* Can't find leaf PTE */
        }

        /* Continue with G-Stage translation? */
        if (!pass && en_g) {
            pass = true;
            addr = base;
            base = gatp;
            sc[pass].step = 0;
        }
    } while (1);

    return (iotlb->perm & IOMMU_WO) ?
                (pass ? RIO_CAUSE_WR_FAULT_G : RIO_CAUSE_WR_FAULT_S) :
                (pass ? RIO_CAUSE_RD_FAULT_G : RIO_CAUSE_RD_FAULT_S);
}

/*
 * RISC-V IOMMU Device Context Loopkup - Device Directory Tree Walk
 *
 * @s         : IOMMU Device State
 * @ctx       : Device Translation Context with devid set.
 * @return    : success or fault code.
 */
static int riscv_iommu_ctx_fetch(RISCVIOMMUState *s, RISCVIOMMUContext *ctx)
{
    const uint64_t ddtp = s->ddtp;
    unsigned mode = get_field(ddtp, RIO_DDTP_MASK_MODE);
    dma_addr_t addr = PPN_PHYS(get_field(ddtp, RIO_DDTP_MASK_PPN));
    const bool dcbase = true; /* DC format mode: 1: BASE | 0: EXTENDED */
    unsigned depth;
    uint64_t de;
    RISCVIOMMUDeviceContext dc;

    switch (mode) {
    case RIO_DDTP_MODE_OFF:
        return RIO_CAUSE_DMA_DISABLED;

    case RIO_DDTP_MODE_BARE:
        /* mock up pass-through translation context */
        ctx->gatp = set_field(0, RIO_ATP_MASK_MODE, RIO_ATP_MODE_BARE);
        ctx->satp = set_field(0, RIO_ATP_MASK_MODE, RIO_ATP_MODE_BARE);
        ctx->tc = RIO_DCTC_EN_ATS | RIO_DCTC_VALID;
        ctx->ta = 0;
        return 0;

    case RIO_DDTP_MODE_1LVL:
        depth = 0;
        break;

    case RIO_DDTP_MODE_2LVL:
        depth = 1;
        break;

    case RIO_DDTP_MODE_3LVL:
        depth = 2;
        break;

    default:
        return RIO_CAUSE_DDT_UNSUPPORTED;
    }

    /* Check supported device id range. */
    if (ctx->devid >= (1 << (depth * 9 + 6 + (dcbase && depth != 2)))) {
        return RIO_CAUSE_DDT_INVALID;
    }

    /* Device directory tree walk */
    for (; depth-- > 0; ) {
        const int split = depth * 9 + 6 + dcbase;
        addr |= ((ctx->devid >> split) << 3) & ~TARGET_PAGE_MASK;
        if (dma_memory_read(s->target_as, addr, &de, sizeof(de),
                            MEMTXATTRS_UNSPECIFIED) != MEMTX_OK) {
            return RIO_CAUSE_DDT_FAULT;
        }
        le64_to_cpus(&de);
        if (!(de & RIO_DCTC_VALID)) {
            return RIO_CAUSE_DDT_INVALID; /* invalid directory entry */
        }
        if (de & ~(RIO_DDTE_MASK_PPN | RIO_DCTC_VALID)) {
            return RIO_CAUSE_DDT_INVALID; /* reserved bits set. */
        }
        addr = PPN_PHYS(get_field(de, RIO_DDTE_MASK_PPN));
    }

    /* index into device context entry page */
    const size_t dcsize = sizeof(dc) >> dcbase;
    addr |= (ctx->devid * dcsize) & ~TARGET_PAGE_MASK;

    memset(&dc, 0, sizeof(dc));
    if (dma_memory_read(s->target_as, addr, &dc, dcsize,
                        MEMTXATTRS_UNSPECIFIED) != MEMTX_OK) {
        return RIO_CAUSE_DDT_FAULT;
    }

    /* Set translation context. */
    ctx->tc = le64_to_cpu(dc.tc);
    ctx->gatp = le64_to_cpu(dc.gatp);
    ctx->satp = le64_to_cpu(dc.fsc);
    ctx->ta = le64_to_cpu(dc.ta);

    if (!(ctx->tc & RIO_DCTC_VALID)) {
        return RIO_CAUSE_DDT_INVALID;
    }

    /* FSC field checks */
    mode = get_field(ctx->satp, RIO_ATP_MASK_MODE);
    addr = PPN_PHYS(get_field(ctx->satp, RIO_ATP_MASK_PPN));

    if (mode == RIO_PDTP_MODE_BARE) {
        return 0;                       /* No S-Stage translation */
    }

    if (ctx->tc & RIO_DCTC_PDTV) {
        return RIO_CAUSE_REQ_INVALID;   /* No PASID support */
    }

    return 0;
}

/*
 * Return translation context for a given {device_id}.
 * Translation context must be released with riscv_iommu_ctx_put().
 */
static RISCVIOMMUContext *riscv_iommu_ctx(RISCVIOMMUState *s,
        unsigned devid, void **ref)
{
    RISCVIOMMUContext *ctx;

    ctx = g_new0(RISCVIOMMUContext, 1);
    ctx->devid = devid;

    int fault = riscv_iommu_ctx_fetch(s, ctx);
    if (!fault) {
        *ref = ctx;
        return ctx;
    }

    if (!(ctx->tc & RIO_DCTC_DTF)) {
        RISCVIOMMUEvent ev = {
            .reason = set_field(set_field(ctx->devid,
                        RIO_EVENT_MASK_CAUSE, fault),
                        RIO_EVENT_MASK_TTYPE, RIO_TTYP_URD),
            .iova   = 0,
            .phys   = 0,
            ._rsrvd = 0,
        };
        riscv_iommu_fault(s, &ev);
    }

    g_free(ctx);
    return NULL;
}

static void riscv_iommu_ctx_put(RISCVIOMMUState *s, void *ref)
{
    if (ref) {
        g_free(ref);
    }
}

/* Find or allocate address space for a given device */
static RISCVIOMMUSpace *riscv_iommu_space(RISCVIOMMUState *s, uint32_t devid)
{
    RISCVIOMMUSpace *as;

    if (s->devid == devid) {
        return NULL;
    }

    if (PCI_BUS_NUM(s->devid) != PCI_BUS_NUM(devid)) {
        /* Handle only devices on the same bus as IOMMU device. */
        return NULL;
    }

    qemu_mutex_lock(&s->core_lock);
    QLIST_FOREACH(as, &s->spaces, list) {
        if (as->devid == devid) {
            break;
        }
    }
    qemu_mutex_unlock(&s->core_lock);

    if (as == NULL) {
        char name[64];
        as = g_new0(RISCVIOMMUSpace, 1);

        as->iommu = s;
        as->devid = devid;

        snprintf(name, sizeof(name), "riscv-iommu-%04x:%02x.%d-iova",
            PCI_BUS_NUM(as->devid), PCI_SLOT(as->devid), PCI_FUNC(as->devid));

        /* IOVA address space, untranslated addresses */
        memory_region_init_iommu(&as->iova_mr, sizeof(as->iova_mr),
            TYPE_RISCV_IOMMU_MEMORY_REGION,
            OBJECT(as), name, UINT64_MAX);
        address_space_init(&as->iova_as, MEMORY_REGION(&as->iova_mr),
            TYPE_RISCV_IOMMU_PCI);

        qemu_mutex_lock(&s->core_lock);
        QLIST_INSERT_HEAD(&s->spaces, as, list);
        qemu_mutex_unlock(&s->core_lock);

        trace_riscv_iommu_new(PCI_BUS_NUM(s->devid), PCI_SLOT(s->devid),
            PCI_FUNC(s->devid), PCI_BUS_NUM(as->devid), PCI_SLOT(as->devid),
            PCI_FUNC(as->devid));
    }
    return as;
}

static int riscv_iommu_translate(RISCVIOMMUState *s, RISCVIOMMUContext *ctx,
        IOMMUTLBEntry *iotlb)
{
    bool enable_faults = true;
    int fault;

    enable_faults = !(ctx->tc & RIO_DCTC_DTF);

    /* Check for ATS request while ATS is disabled */
    if ((iotlb->perm == IOMMU_NONE) && !(ctx->tc & RIO_DCTC_EN_ATS)) {
        fault = RIO_CAUSE_REQ_INVALID;
        goto done;
    }

    /* Translate using device directory / page table information. */
    fault = riscv_iommu_spa_fetch(s, ctx, iotlb, false);

done:
    if (enable_faults && fault) {
        RISCVIOMMUEvent ev;
        const unsigned ttype = (iotlb->perm & IOMMU_RW) ? RIO_TTYP_UWR :
                ((iotlb->perm & IOMMU_RO) ? RIO_TTYP_URD : RIO_TTYP_ATS);
        ev.reason = set_field(ctx->devid, RIO_EVENT_MASK_CAUSE, fault);
        ev.reason = set_field(ev.reason, RIO_EVENT_MASK_TTYPE, ttype);
        ev.iova   = iotlb->iova;
        ev.phys   = iotlb->translated_addr;
        ev._rsrvd = 0;
        riscv_iommu_fault(s, &ev);
    }

    return fault;
}

/* IOMMU Command Interface */
static void riscv_iommu_iofence(RISCVIOMMUState *s, bool notify,
        uint64_t addr, uint32_t data)
{
    if (!notify) {
        return;
    }

    if (dma_memory_write(s->target_as, addr, &data, sizeof(data),
            MEMTXATTRS_UNSPECIFIED) != MEMTX_OK) {
        riscv_iommu_reg_mod32(s, RIO_REG_CQCSR, RIO_CQ_FAULT, 0);
    }
}

static void riscv_iommu_process_ddtp(RISCVIOMMUState *s)
{
    uint64_t old_ddtp = s->ddtp;
    uint64_t new_ddtp = riscv_iommu_reg_get64(s, RIO_REG_DDTP);
    unsigned new_mode = get_field(new_ddtp, RIO_DDTP_MASK_MODE);
    unsigned old_mode = get_field(old_ddtp, RIO_DDTP_MASK_MODE);
    bool ok = false;

    /*
     * Check for allowed DDTP.MODE transitions:
     * {OFF, BARE}        -> {OFF, BARE, 1LVL, 2LVL, 3LVL}
     * {1LVL, 2LVL, 3LVL} -> {OFF, BARE}
     */
    if (new_mode == old_mode ||
        new_mode == RIO_DDTP_MODE_OFF ||
        new_mode == RIO_DDTP_MODE_BARE) {
        ok = true;
    } else if (new_mode == RIO_DDTP_MODE_1LVL ||
               new_mode == RIO_DDTP_MODE_2LVL ||
               new_mode == RIO_DDTP_MODE_3LVL) {
        ok = old_mode == RIO_DDTP_MODE_OFF ||
             old_mode == RIO_DDTP_MODE_BARE;
    }

    if (ok) {
        /* clear reserved and busy bits, report back sanitized version */
        new_ddtp = set_field(new_ddtp & RIO_DDTP_MASK_PPN,
                             RIO_DDTP_MASK_MODE, new_mode);
    } else {
        new_ddtp = old_ddtp;
    }
    s->ddtp = new_ddtp;

    /* System software is not allowed to modify DDTP while BUSY bit is set. */
    riscv_iommu_reg_set64(s, RIO_REG_DDTP, new_ddtp);
}

static void riscv_iommu_process_cq_tail(RISCVIOMMUState *s)
{
    RISCVIOMMUCommand cmd;
    MemTxResult res;
    dma_addr_t addr;
    uint32_t tail, head, ctrl;

    ctrl = riscv_iommu_reg_get32(s, RIO_REG_CQCSR);
    tail = riscv_iommu_reg_get32(s, RIO_REG_CQT) & s->cq_mask;
    head = riscv_iommu_reg_get32(s, RIO_REG_CQH) & s->cq_mask;

    /* Check for pending error or queue processing disabled */
    if (!(ctrl & RIO_CQ_ACTIVE) || !!(ctrl & (RIO_CQ_ERROR | RIO_CQ_FAULT))) {
        return;
    }

    while (tail != head) {
        addr = s->cq_addr  + head * sizeof(cmd);
        res = dma_memory_read(s->target_as, addr, &cmd, sizeof(cmd),
                              MEMTXATTRS_UNSPECIFIED);

        if (res != MEMTX_OK) {
            riscv_iommu_reg_mod32(s, RIO_REG_CQCSR, RIO_CQ_FAULT, 0);
            goto fault;
        }

        head = (head + 1) & s->cq_mask;

        /* Update head pointer after fetch, before execution */
        riscv_iommu_reg_set32(s, RIO_REG_CQH, head);

        trace_riscv_iommu_cmd(PCI_BUS_NUM(s->devid), PCI_SLOT(s->devid),
                              PCI_FUNC(s->devid), cmd.request, cmd.address);

        switch (get_field(cmd.request, RIO_CMD_MASK_OP)) {
        case RIO_CMD_IOFENCE:
            riscv_iommu_iofence(s,
                    !!(cmd.request & RIO_IOFENCE_AV), cmd.address,
                    get_field(cmd.request, RIO_IOFENCE_MASK_DATA));
            break;

        case RIO_CMD_IOTINVAL:
            break;

        case RIO_CMD_IODIR:
            break;

        default:
            /* Invalid instruction, do not advance instruction index. */
            riscv_iommu_reg_mod32(s, RIO_REG_CQCSR, RIO_CQ_ERROR, 0);
            goto fault;
        }
    }

fault:
    if (ctrl & RIO_CQ_IE) {
        riscv_iommu_irq_assert(s, RIO_INT_CQ);
    }
}

static void riscv_iommu_process_cq_control(RISCVIOMMUState *s)
{
    uint64_t base;
    uint32_t ctrl_set = riscv_iommu_reg_get32(s, RIO_REG_CQCSR);
    uint32_t ctrl_clr;
    bool enable = !!(ctrl_set & RIO_FQ_EN);
    bool active = !!(ctrl_set & RIO_FQ_ACTIVE);

    if (enable && !active) {
        base = riscv_iommu_reg_get64(s, RIO_REG_CQB);
        s->cq_mask = (2ULL << get_field(base, RIO_CQ_MASK_LOG2SZ)) - 1;
        s->cq_addr = PPN_PHYS(get_field(base, RIO_CQ_MASK_PPN));
        stl_le_p(&s->regs_ro[RIO_REG_CQT], ~s->cq_mask);
        stl_le_p(&s->regs_rw[RIO_REG_CQH], 0);
        stl_le_p(&s->regs_rw[RIO_REG_CQT], 0);
        ctrl_set = RIO_CQ_ACTIVE;
        ctrl_clr = RIO_CQ_BUSY | RIO_CQ_FAULT | RIO_CQ_ERROR | RIO_CQ_TIMEOUT;
    } else if (!enable && active) {
        stl_le_p(&s->regs_ro[RIO_REG_CQT], ~0);
        ctrl_set = 0;
        ctrl_clr = RIO_CQ_BUSY | RIO_CQ_ACTIVE;
    } else {
        ctrl_set = 0;
        ctrl_clr = RIO_CQ_BUSY;
    }

    riscv_iommu_reg_mod32(s, RIO_REG_CQCSR, ctrl_set, ctrl_clr);
}

static void riscv_iommu_process_fq_control(RISCVIOMMUState *s)
{
    uint64_t base;
    uint32_t ctrl_set = riscv_iommu_reg_get32(s, RIO_REG_FQCSR);
    uint32_t ctrl_clr;
    bool enable = !!(ctrl_set & RIO_FQ_EN);
    bool active = !!(ctrl_set & RIO_FQ_ACTIVE);

    if (enable && !active) {
        base = riscv_iommu_reg_get64(s, RIO_REG_FQB);
        s->fq_mask = (2ULL << get_field(base, RIO_FQ_MASK_LOG2SZ)) - 1;
        s->fq_addr = PPN_PHYS(get_field(base, RIO_FQ_MASK_PPN));
        stl_le_p(&s->regs_ro[RIO_REG_FQH], ~s->fq_mask);
        stl_le_p(&s->regs_rw[RIO_REG_FQH], 0);
        stl_le_p(&s->regs_rw[RIO_REG_FQT], 0);
        ctrl_set = RIO_FQ_ACTIVE;
        ctrl_clr = RIO_FQ_BUSY | RIO_FQ_FAULT | RIO_FQ_FULL;
    } else if (!enable && active) {
        stl_le_p(&s->regs_ro[RIO_REG_FQH], ~0);
        ctrl_set = 0;
        ctrl_clr = RIO_FQ_BUSY | RIO_FQ_ACTIVE;
    } else {
        ctrl_set = 0;
        ctrl_clr = RIO_FQ_BUSY;
    }

    riscv_iommu_reg_mod32(s, RIO_REG_FQCSR, ctrl_set, ctrl_clr);
}

static void riscv_iommu_process_pq_control(RISCVIOMMUState *s)
{
    uint64_t base;
    uint32_t ctrl_set = riscv_iommu_reg_get32(s, RIO_REG_PQCSR);
    uint32_t ctrl_clr;
    bool enable = !!(ctrl_set & RIO_PQ_EN);
    bool active = !!(ctrl_set & RIO_PQ_ACTIVE);

    if (enable && !active) {
        base = riscv_iommu_reg_get64(s, RIO_REG_PQB);
        s->pq_mask = (2ULL << get_field(base, RIO_PQ_MASK_LOG2SZ)) - 1;
        s->pq_addr = PPN_PHYS(get_field(base, RIO_PQ_MASK_PPN));
        stl_le_p(&s->regs_ro[RIO_REG_PQH], ~s->pq_mask);
        stl_le_p(&s->regs_rw[RIO_REG_PQH], 0);
        stl_le_p(&s->regs_rw[RIO_REG_PQT], 0);
        ctrl_set = RIO_PQ_ACTIVE;
        ctrl_clr = RIO_PQ_BUSY | RIO_PQ_FAULT | RIO_PQ_FULL;
    } else if (!enable && active) {
        stl_le_p(&s->regs_ro[RIO_REG_PQH], ~0);
        ctrl_set = 0;
        ctrl_clr = RIO_PQ_BUSY | RIO_PQ_ACTIVE;
    } else {
        ctrl_set = 0;
        ctrl_clr = RIO_PQ_BUSY;
    }

    riscv_iommu_reg_mod32(s, RIO_REG_PQCSR, ctrl_set, ctrl_clr);
}

static void riscv_iommu_process_dbg(RISCVIOMMUState *s)
{
    uint64_t iova = riscv_iommu_reg_get64(s, RIO_REG_TR_REQ_IOVA);
    uint64_t ctrl = riscv_iommu_reg_get64(s, RIO_REG_TR_REQ_CTRL);
    unsigned devid = (unsigned)((ctrl >> 16) & ((1UL << 20) - 1));
    RISCVIOMMUContext *ctx;
    void *ref;

    if (!(ctrl & RIO_TRREQ_BUSY)) {
        return;
    }

    ctx = riscv_iommu_ctx(s, devid, &ref);
    if (ctx == NULL) {
        riscv_iommu_reg_set64(s, RIO_REG_TR_RESPONSE,
                RIO_TRRSP_FAULT | (RIO_CAUSE_DMA_DISABLED << 10));
    } else {
        IOMMUTLBEntry iotlb = {
            .iova = iova,
            .perm = IOMMU_NONE,
            .addr_mask = ~0,
            .target_as = NULL,
        };
        int fault = riscv_iommu_translate(s, ctx, &iotlb);
        if (fault) {
            iova = RIO_TRRSP_FAULT | (((uint64_t) fault) << 10);
        } else {
            iova = ((iotlb.translated_addr & ~iotlb.addr_mask) >> 2) &
                    RIO_TRRSP_MASK_PPN;
        }
        riscv_iommu_reg_set64(s, RIO_REG_TR_RESPONSE, iova);
    }

    riscv_iommu_reg_mod64(s, RIO_REG_TR_REQ_CTRL, 0, RIO_TRREQ_BUSY);
    riscv_iommu_ctx_put(s, ref);
}

/* Core IOMMU execution activations */
enum {
    RIO_EXEC_DDTP,
    RIO_EXEC_CQCSR,
    RIO_EXEC_CQT,
    RIO_EXEC_FQCSR,
    RIO_EXEC_FQH,
    RIO_EXEC_PQCSR,
    RIO_EXEC_PQH,
    RIO_EXEC_TR_REQUEST,
    RIO_EXEC_EXIT,  /* must be the last enum value */
};

static void *riscv_iommu_core_proc(void* arg)
{
    RISCVIOMMUState *s = arg;
    unsigned exec = 0;
    unsigned mask = 0;

    while (!(exec & BIT(RIO_EXEC_EXIT))) {
        mask = (mask ? mask : BIT(RIO_EXEC_EXIT)) >> 1;
        switch (exec & mask) {
        case BIT(RIO_EXEC_DDTP):
            riscv_iommu_process_ddtp(s);
            break;
        case BIT(RIO_EXEC_CQCSR):
            riscv_iommu_process_cq_control(s);
            break;
        case BIT(RIO_EXEC_CQT):
            riscv_iommu_process_cq_tail(s);
            break;
        case BIT(RIO_EXEC_FQCSR):
            riscv_iommu_process_fq_control(s);
            break;
        case BIT(RIO_EXEC_FQH):
            /* NOP */
            break;
        case BIT(RIO_EXEC_PQCSR):
            riscv_iommu_process_pq_control(s);
            break;
        case BIT(RIO_EXEC_PQH):
            /* NOP */
            break;
        case BIT(RIO_EXEC_TR_REQUEST):
            riscv_iommu_process_dbg(s);
            break;
        }
        exec &= ~mask;
        if (!exec) {
            qemu_mutex_lock(&s->core_lock);
            exec = s->core_exec;
            while (!exec) {
                qemu_cond_wait(&s->core_cond, &s->core_lock);
                exec = s->core_exec;
            }
            s->core_exec = 0;
            qemu_mutex_unlock(&s->core_lock);
        }
    };

    return NULL;
}

static MemTxResult riscv_iommu_mmio_write(void *opaque, hwaddr addr,
        uint64_t data, unsigned size, MemTxAttrs attrs)
{
    RISCVIOMMUState *s = opaque;
    uint32_t busy = 0;
    uint32_t regb = addr & ~3;
    uint32_t exec = 0;

    if (size == 0 || size > 8 || (addr & (size - 1)) != 0) {
        /* Unsupported MMIO alignment or access size */
        return MEMTX_ERROR;
    }

    if (addr + size > sizeof(s->regs_rw)) {
        /* Unsupported MMIO access location. */
        return MEMTX_ACCESS_ERROR;
    }

    /* Track actionable MMIO write. */
    switch (regb) {
    case RIO_REG_DDTP:
    case RIO_REG_DDTP + 4:
        exec = BIT(RIO_EXEC_DDTP);
        regb = RIO_REG_DDTP;
        busy = RIO_DDTP_BUSY;
        break;

    case RIO_REG_CQT:
        exec = BIT(RIO_EXEC_CQT);
        break;

    case RIO_REG_CQCSR:
        exec = BIT(RIO_EXEC_CQCSR);
        busy = RIO_CQ_BUSY;
        break;

    case RIO_REG_FQH:
        exec = BIT(RIO_EXEC_FQH);
        break;

    case RIO_REG_FQCSR:
        exec = BIT(RIO_EXEC_FQCSR);
        busy = RIO_FQ_BUSY;
        break;

    case RIO_REG_PQH:
        exec = BIT(RIO_EXEC_PQH);
        break;

    case RIO_REG_PQCSR:
        exec = BIT(RIO_EXEC_PQCSR);
        busy = RIO_PQ_BUSY;
        break;

    case RIO_REG_TR_REQ_CTRL:
    case RIO_REG_TR_REQ_CTRL + 4:
        exec = BIT(RIO_EXEC_TR_REQUEST);
        regb = RIO_REG_TR_REQ_CTRL;
        busy = RIO_TRREQ_BUSY;
        break;
    }

    /*
     * Registers update might be not synchronized with core logic.
     * If system software updates register when relevant BUSY bit is set
     * IOMMU behavior of additional writes to the register is UNSPECIFIED
     */

    qemu_spin_lock(&s->regs_lock);
    if (size == 1) {
        uint8_t ro = s->regs_ro[addr];
        uint8_t wc = s->regs_wc[addr];
        uint8_t rw = s->regs_rw[addr];
        s->regs_rw[addr] = ((rw & ro) | (data & ~ro)) & ~(data & wc);
    } else if (size == 2) {
        uint16_t ro = lduw_le_p(&s->regs_ro[addr]);
        uint16_t wc = lduw_le_p(&s->regs_wc[addr]);
        uint16_t rw = lduw_le_p(&s->regs_rw[addr]);
        stw_le_p(&s->regs_rw[addr], ((rw & ro) | (data & ~ro)) & ~(data & wc));
    } else if (size == 4) {
        uint32_t ro = ldl_le_p(&s->regs_ro[addr]);
        uint32_t wc = ldl_le_p(&s->regs_wc[addr]);
        uint32_t rw = ldl_le_p(&s->regs_rw[addr]);
        stl_le_p(&s->regs_rw[addr], ((rw & ro) | (data & ~ro)) & ~(data & wc));
    } else if (size == 8) {
        uint64_t ro = ldq_le_p(&s->regs_ro[addr]);
        uint64_t wc = ldq_le_p(&s->regs_wc[addr]);
        uint64_t rw = ldq_le_p(&s->regs_rw[addr]);
        stq_le_p(&s->regs_rw[addr], ((rw & ro) | (data & ~ro)) & ~(data & wc));
    }

    /* Busy flag update, MSB 4-byte register. */
    if (busy) {
        uint32_t rw = ldl_le_p(&s->regs_rw[regb]);
        stl_le_p(&s->regs_rw[regb], rw | busy);
    }
    qemu_spin_unlock(&s->regs_lock);

    /* Wakeup core processing thread. */
    if (exec) {
        qemu_mutex_lock(&s->core_lock);
        s->core_exec |= exec;
        qemu_cond_signal(&s->core_cond);
        qemu_mutex_unlock(&s->core_lock);
    }

    return MEMTX_OK;
}

static MemTxResult riscv_iommu_mmio_read(void *opaque, hwaddr addr,
        uint64_t *data, unsigned size, MemTxAttrs attrs)
{
    RISCVIOMMUState *s = opaque;
    uint64_t val = -1;

    if (addr + size > sizeof(s->regs_rw)) {
        return MEMTX_ACCESS_ERROR;
    }

    if (size == 1) {
        val = (uint64_t) s->regs_rw[addr];
    } else if (size == 2) {
        val = lduw_le_p(&s->regs_rw[addr]);
    } else if (size == 4) {
        val = ldl_le_p(&s->regs_rw[addr]);
    } else if (size == 8) {
        val = ldq_le_p(&s->regs_rw[addr]);
    } else {
        return MEMTX_ERROR;
    }

    *data = val;

    return MEMTX_OK;
}

static const MemoryRegionOps riscv_iommu_mmio_ops = {
    .read_with_attrs = riscv_iommu_mmio_read,
    .write_with_attrs = riscv_iommu_mmio_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .impl = {
        .min_access_size = 1,
        .max_access_size = 8,
        .unaligned = false,
    },
    .valid = {
        .min_access_size = 1,
        .max_access_size = 8,
    }
};

static void riscv_iommu_init(RISCVIOMMUState *s)
{
    s->cap = s->version & RIO_CAP_REV_MASK;
    if (s->enable_ats) {
        s->cap |= RIO_CAP_ATS;
    }
    if (s->enable_s_stage) {
        s->cap |= RIO_CAP_S_SV32 | RIO_CAP_S_SV39 |
                  RIO_CAP_S_SV48 | RIO_CAP_S_SV57;
    }
    if (s->enable_g_stage) {
        s->cap |= RIO_CAP_G_SV32 | RIO_CAP_G_SV39 |
                  RIO_CAP_G_SV48 | RIO_CAP_G_SV57;
    }
    /* Enable translation debug interface */
    s->cap |= RIO_CAP_DBG;

    /* Report QEMU target physical address space limits */
    s->cap = set_field(s->cap, RIO_CAP_PAS_MASK, TARGET_PHYS_ADDR_SPACE_BITS);

    /* Out-of-reset translation mode: OFF (DMA disabled) BARE (passthrough) */
    s->ddtp = set_field(0, RIO_DDTP_MASK_MODE, s->enable_off ?
                        RIO_DDTP_MODE_OFF : RIO_DDTP_MODE_BARE);

    /* Mark all registers read-only */
    memset(s->regs_ro, 0xff, sizeof(s->regs_ro));
    memset(s->regs_rw, 0x00, sizeof(s->regs_rw));
    memset(s->regs_wc, 0x00, sizeof(s->regs_wc));

    /* Set power-on register state */
    stq_le_p(&s->regs_rw[RIO_REG_CAP], s->cap);
    stq_le_p(&s->regs_ro[RIO_REG_DDTP],
        ~(RIO_DDTP_MASK_PPN | RIO_DDTP_MASK_MODE));
    stq_le_p(&s->regs_ro[RIO_REG_CQB],
        ~(RIO_CQ_MASK_LOG2SZ | RIO_CQ_MASK_PPN));
    stq_le_p(&s->regs_ro[RIO_REG_FQB],
        ~(RIO_FQ_MASK_LOG2SZ | RIO_FQ_MASK_PPN));
    stq_le_p(&s->regs_ro[RIO_REG_PQB],
        ~(RIO_PQ_MASK_LOG2SZ | RIO_PQ_MASK_PPN));
    stl_le_p(&s->regs_wc[RIO_REG_CQCSR],
        RIO_CQ_FAULT | RIO_CQ_TIMEOUT | RIO_CQ_ERROR);
    stl_le_p(&s->regs_ro[RIO_REG_CQCSR], RIO_CQ_ACTIVE | RIO_CQ_BUSY);
    stl_le_p(&s->regs_wc[RIO_REG_FQCSR], RIO_FQ_FAULT | RIO_FQ_FULL);
    stl_le_p(&s->regs_ro[RIO_REG_FQCSR], RIO_FQ_ACTIVE | RIO_FQ_BUSY);
    stl_le_p(&s->regs_wc[RIO_REG_PQCSR], RIO_PQ_FAULT | RIO_PQ_FULL);
    stl_le_p(&s->regs_ro[RIO_REG_PQCSR], RIO_PQ_ACTIVE | RIO_PQ_BUSY);
    stl_le_p(&s->regs_wc[RIO_REG_IPSR], ~0);
    stl_le_p(&s->regs_ro[RIO_REG_IVEC], 0);
    stq_le_p(&s->regs_rw[RIO_REG_DDTP], s->ddtp);
    /* If debug registers enabled. */
    if (s->cap & RIO_CAP_DBG) {
        stq_le_p(&s->regs_ro[RIO_REG_TR_REQ_IOVA], 0);
        stq_le_p(&s->regs_ro[RIO_REG_TR_REQ_CTRL], RIO_TRREQ_BUSY);
    }

    s->iommus.le_next = NULL;
    s->iommus.le_prev = NULL;
    QLIST_INIT(&s->spaces);
    qemu_cond_init(&s->core_cond);
    qemu_mutex_init(&s->core_lock);
    qemu_spin_init(&s->regs_lock);
    qemu_thread_create(&s->core_proc, "riscv-iommu-core",
        riscv_iommu_core_proc, s, QEMU_THREAD_JOINABLE);
}

static void riscv_iommu_exit(RISCVIOMMUState *s)
{
    qemu_mutex_lock(&s->core_lock);
    s->core_exec = BIT(RIO_EXEC_EXIT); /* cancel pending operations and stop */
    qemu_cond_signal(&s->core_cond);
    qemu_mutex_unlock(&s->core_lock);
    qemu_thread_join(&s->core_proc);
    qemu_cond_destroy(&s->core_cond);
    qemu_mutex_destroy(&s->core_lock);
}

static AddressSpace *riscv_iommu_find_as(PCIBus *bus, void *opaque, int devid)
{
    RISCVIOMMUState *s = (RISCVIOMMUState *) opaque;
    RISCVIOMMUSpace *as = NULL;

    /* Find first registered IOMMU device */
    while (s->iommus.le_prev) {
        s = *(s->iommus.le_prev);
    }

    /* Find first matching IOMMU */
    while (s != NULL && as == NULL) {
        as = riscv_iommu_space(s, PCI_BUILD_BDF(pci_bus_num(bus), devid));
        s = s->iommus.le_next;
    }

    return as ? &as->iova_as : &address_space_memory;
}

/* RISC-V IOMMU PCI Device Emulation */

struct RISCVIOMMUStatePci {
    PCIDevice        pci;     /* Parent PCIe device state */
    MemoryRegion     bar0;    /* PCI BAR (including MSI-x config) */
    MemoryRegion     regs;    /* PCI MMIO interface */
    RISCVIOMMUState  iommu;   /* common IOMMU state */
};

/* interrupt delivery callback */
static void riscv_iommu_pci_notify(RISCVIOMMUState *iommu, unsigned vector)
{
    RISCVIOMMUStatePci *s = container_of(iommu, RISCVIOMMUStatePci, iommu);

    if (msix_enabled(&(s->pci))) {
        msix_notify(&(s->pci), vector);
    }
}

static void riscv_iommu_pci_realize(PCIDevice *dev, Error **errp)
{
    DeviceState *d = DEVICE(dev);
    RISCVIOMMUStatePci *s = RISCV_IOMMU_PCI(d);
    RISCVIOMMUState *iommu = &s->iommu;
    const uint64_t bar_size =
        pow2ceil(QEMU_ALIGN_UP(sizeof(iommu->regs_rw), TARGET_PAGE_SIZE));
    Error *err = NULL;

    iommu->devid = pci_get_bdf(dev);

    riscv_iommu_init(iommu);

    memory_region_init(&s->bar0, OBJECT(s),
            "riscv-iommu-bar0", bar_size);
    /* Register only device accessible MMIO space, up to RIO_REG_MSI_CONFIG. */
    memory_region_init_io(&s->regs, OBJECT(s), &riscv_iommu_mmio_ops, iommu,
            "riscv-iommu-regs", RIO_REG_MSI_CONFIG);
    memory_region_add_subregion(&s->bar0, 0, &s->regs);

    pcie_endpoint_cap_init(dev, 0);

    pci_register_bar(dev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY |
            PCI_BASE_ADDRESS_MEM_TYPE_64, &s->bar0);

    int ret = msix_init(dev, RIO_INT_COUNT,
                    &s->bar0, 0, RIO_REG_MSI_CONFIG,
                    &s->bar0, 0, RIO_REG_MSI_CONFIG + 256, 0, &err);

    if (ret == -ENOTSUP) {
        /*
         * MSI-x is not supported by the platform.
         * Driver should use timer/polling based notification handlers.
         */
        warn_report_err(err);
    } else if (ret < 0) {
        error_propagate(errp, err);
        return;
    } else {
        /* mark all allocated MSIx vectors as used. */
        while (ret-- > 0) {
            msix_vector_use(dev, ret);
        }
        iommu->notify = riscv_iommu_pci_notify;
    }

    if (iommu->down_mr) {
        iommu->target_as = g_new0(AddressSpace, 1);
        address_space_init(iommu->target_as, iommu->down_mr,
                "riscv-iommu-downstream");
    } else {
        /* Early lookup for IOMMU parent device address space. */
        iommu->target_as = pci_device_iommu_address_space(dev);
    }

    PCIBus *bus = pci_device_root_bus(dev);
    if (!bus) {
        error_setg(errp, "can't find PCIe root port for %02x:%02x.%x",
            pci_bus_num(pci_get_bus(dev)), PCI_SLOT(dev->devfn),
            PCI_FUNC(dev->devfn));
        return;
    }

    if (bus->iommu_fn == riscv_iommu_find_as) {
        /* Allow multiple IOMMUs on the same PCIe bus, link known devices */
        RISCVIOMMUState *last = (RISCVIOMMUState *)bus->iommu_opaque;
        QLIST_INSERT_AFTER(last, iommu, iommus);
    } else if (bus->iommu_fn == NULL) {
        pci_setup_iommu(bus, riscv_iommu_find_as, iommu);
    } else {
        error_setg(errp, "can't register secondary IOMMU for %02x:%02x.%x",
            pci_bus_num(pci_get_bus(dev)), PCI_SLOT(dev->devfn),
            PCI_FUNC(dev->devfn));
    }
}

static void riscv_iommu_pci_exit(PCIDevice *dev)
{
    DeviceState *d = DEVICE(dev);
    RISCVIOMMUStatePci *s = RISCV_IOMMU_PCI(d);

    pci_setup_iommu(pci_device_root_bus(dev), NULL, NULL);
    riscv_iommu_exit(&s->iommu);
}

static const VMStateDescription riscv_iommu_vmstate = {
    .name = "riscv-iommu",
    .unmigratable = 1
};

static Property riscv_iommu_properties[] = {
    DEFINE_PROP_UINT32("version", RISCVIOMMUStatePci, iommu.version, 0x02),
    DEFINE_PROP_BOOL("ats", RISCVIOMMUStatePci, iommu.enable_ats, TRUE),
    DEFINE_PROP_BOOL("off", RISCVIOMMUStatePci, iommu.enable_off, TRUE),
    DEFINE_PROP_BOOL("s-stage", RISCVIOMMUStatePci, iommu.enable_s_stage, TRUE),
    DEFINE_PROP_BOOL("g-stage", RISCVIOMMUStatePci, iommu.enable_g_stage, TRUE),
    DEFINE_PROP_LINK("downstream-mr", RISCVIOMMUStatePci, iommu.down_mr,
            TYPE_MEMORY_REGION, MemoryRegion *),
    DEFINE_PROP_END_OF_LIST(),
};

static void riscv_iommu_pci_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    device_class_set_props(dc, riscv_iommu_properties);
    k->realize = riscv_iommu_pci_realize;
    k->exit = riscv_iommu_pci_exit;
    k->vendor_id = PCI_VENDOR_ID_RIVOS;
    k->device_id = PCI_DEVICE_ID_RIVOS_IOMMU;
    k->revision = 0;
    k->class_id = 0x0806;
    dc->desc = "RISCV-IOMMU DMA Remapping device";
    dc->vmsd = &riscv_iommu_vmstate;
    dc->hotpluggable = false;
    dc->user_creatable = true;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo riscv_iommu_pci = {
    .name = TYPE_RISCV_IOMMU_PCI,
    .parent = TYPE_PCI_DEVICE,
    .instance_size = sizeof(RISCVIOMMUStatePci),
    .class_init = riscv_iommu_pci_init,
    .interfaces = (InterfaceInfo[]) {
        { INTERFACE_PCIE_DEVICE },
        { },
    },
};

static const char *IOMMU_FLAG_STR[] = {
    "NA",
    "RO",
    "WR",
    "RW",
};

/* RISC-V IOMMU Memory Region - Address Translation Space */
static IOMMUTLBEntry riscv_iommu_memory_region_translate(
        IOMMUMemoryRegion *iommu_mr, hwaddr addr,
        IOMMUAccessFlags flag, int iommu_idx)
{
    RISCVIOMMUSpace *as = container_of(iommu_mr, RISCVIOMMUSpace, iova_mr);
    RISCVIOMMUContext *ctx;
    void *ref;
    IOMMUTLBEntry iotlb = {
        .iova = addr,
        .target_as = as->iommu->target_as,
        .addr_mask = ~0ULL,
        .perm = flag,
    };

    ctx = riscv_iommu_ctx(as->iommu, as->devid, &ref);
    if (ctx == NULL) {
        /* Translation disabled or invalid. */
        iotlb.addr_mask = 0;
        iotlb.perm = IOMMU_NONE;
    } else if (riscv_iommu_translate(as->iommu, ctx, &iotlb)) {
        /* Translation disabled or fault reported. */
        iotlb.addr_mask = 0;
        iotlb.perm = IOMMU_NONE;
    }

    /* Trace all dma translations with original access flags. */
    trace_riscv_iommu_dma(PCI_BUS_NUM(as->devid), PCI_SLOT(as->devid),
        PCI_FUNC(as->devid), iommu_idx, IOMMU_FLAG_STR[flag & IOMMU_RW],
        iotlb.iova, iotlb.translated_addr);

    riscv_iommu_ctx_put(as->iommu, ref);
    return iotlb;
}

static int riscv_iommu_memory_region_notify(
    IOMMUMemoryRegion *iommu_mr, IOMMUNotifierFlag old,
    IOMMUNotifierFlag new, Error **errp)
{
    if (new & IOMMU_NOTIFIER_DEVIOTLB_UNMAP) {
        error_setg(errp, "riscv-iommu does not support dev-iotlb");
        return -EINVAL;
    }
    return 0;
}

static void riscv_iommu_memory_region_init(ObjectClass *klass, void *data)
{
    IOMMUMemoryRegionClass *imrc = IOMMU_MEMORY_REGION_CLASS(klass);

    imrc->translate = riscv_iommu_memory_region_translate;
    imrc->notify_flag_changed = riscv_iommu_memory_region_notify;
}

static const TypeInfo riscv_iommu_memory_region_info = {
    .parent = TYPE_IOMMU_MEMORY_REGION,
    .name = TYPE_RISCV_IOMMU_MEMORY_REGION,
    .class_init = riscv_iommu_memory_region_init,
};

static void riscv_iommu_register_types(void)
{
    type_register_static(&riscv_iommu_memory_region_info);
    type_register_static(&riscv_iommu_pci);
}

type_init(riscv_iommu_register_types);
