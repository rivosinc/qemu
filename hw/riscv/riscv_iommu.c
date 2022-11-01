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

#include "cpu_bits.h"
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
#include "qemu/host-utils.h"
#include "qemu/timer.h"

#include "trace.h"

#ifndef PCI_VENDOR_ID_RIVOS
#define PCI_VENDOR_ID_RIVOS           0x1efd
#endif

#ifndef PCI_DEVICE_ID_RIVOS_IOMMU
#define PCI_DEVICE_ID_RIVOS_IOMMU     0xedf1
#endif

#define LIMIT_CACHE_CTX               (1U << 7)
#define LIMIT_CACHE_IOT               (1U << 20)

/* Physical page number coversions */
#define PPN_PHYS(ppn)                 ((ppn) << TARGET_PAGE_BITS)
#define PPN_DOWN(phy)                 ((phy) >> TARGET_PAGE_BITS)

typedef struct RISCVIOMMUContext RISCVIOMMUContext;
typedef struct RISCVIOMMUEntry   RISCVIOMMUEntry;
typedef struct RISCVIOMMUState   RISCVIOMMUState;

struct RISCVIOMMUState {
    uint32_t devid;       /* requester Id, 0 if not assigned. */
    uint32_t version;     /* Reported interface version number */
    uint32_t pasid_bits;  /* process identifier width */

    uint64_t cap;         /* IOMMU supported capabitilites */

    bool enable_off;      /* Enable out-of-reset OFF mode (DMA disabled) */
    bool enable_msi;      /* Enable MSI remapping */
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

    GHashTable *ctx_cache;          /* Device translation Context Cache */
    GHashTable *iot_cache;          /* IO Translated Address Cache */

    /* HPM cycle counter */
    QEMUTimer *hpm_timer;
    uint64_t hpmcycle_val;      /* Current value of cycle register */
    uint64_t hpmcycle_prev;     /* Saved value of QEMU_CLOCK_VIRTUAL clock */
    uint64_t irq_overflow_left; /* Value beyond INT64_MAX after overflow */

    /* HPM event counters */
    uint8_t hpm_cntrs;
    GHashTable *hpm_event_ctr_map; /* Mapping of events to counters */
    pthread_rwlock_t ht_lock;      /* Lock used for hpm_event_ctr_map updates */

    AddressSpace trap_as;           /* MRIF/MSI access trap address space */
    MemoryRegion trap_mr;           /* MRIF/MSI access trap memory region */
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
    uint64_t pasid:20;          /* Process Address Space ID */
    uint64_t __rfu:20;          /* reserved */
    uint64_t tc;                /* Translation Control */
    uint64_t ta;                /* Translation Attributes */
    uint64_t satp;              /* S-Stage address translation and protection */
    uint64_t gatp;              /* G-Stage address translation and protection */
    uint64_t msi_addr_mask;     /* MSI filtering - address mask */
    uint64_t msi_addr_pattern;  /* MSI filtering - address pattern */
    uint64_t msi_redirect;      /* MSI redirection page table pointer */
};

/* iot_cache elements, IOATC entry */
struct RISCVIOMMUEntry {
    uint64_t iova:44;           /* IOVA Page Number */
    uint64_t pscid:20;          /* Process Soft-Context identifier */
    uint64_t phys:44;           /* Physical Page Number */
    uint64_t gscid:16;          /* Guest Soft-Context identifier */
    uint64_t perm:2;            /* IOMMU_RW flags */
    uint64_t __rfu:2;
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

static void __hpm_incr_ctr(RISCVIOMMUState *s, uint32_t ctr_idx)
{
    const uint32_t off = ctr_idx << 3;
    uint64_t cntr_val;

    qemu_spin_lock(&s->regs_lock);
    cntr_val = ldq_le_p(&s->regs_rw[RIO_REG_IOHPMCTR_BASE + off]);
    stq_le_p(&s->regs_rw[RIO_REG_IOHPMCTR_BASE + off], cntr_val + 1);
    qemu_spin_unlock(&s->regs_lock);

    /* Handle the overflow scenario. */
    if (cntr_val == UINT64_MAX) {
        /*
         * Generate interrupt only if OF bit is clear. +1 to offset the cycle
         * register OF bit.
         */
        const uint32_t ovf =
            riscv_iommu_reg_mod32(s, RIO_REG_IOCNTOVF, BIT(ctr_idx + 1), 0);
        if (!get_field(ovf, BIT(ctr_idx + 1))) {
            riscv_iommu_reg_mod64(s,
                                  RIO_REG_IOHPMEVT_BASE + off,
                                  RIO_IOHPMEVT_OF,
                                  0);
            riscv_iommu_irq_assert(s, RIO_INT_PM);
        }
    }
}

static void riscv_iommu_hpm_incr_ctr(RISCVIOMMUState *s,
                                     RISCVIOMMUContext *ctx,
                                     enum RISCVIOMMUEventID event_id)
{
    const uint32_t inhibit = riscv_iommu_reg_get32(s, RIO_REG_IOCNTINH);
    uint32_t did_gscid;
    uint32_t pid_pscid;
    uint32_t ctr_idx;
    gpointer value;
    uint32_t ctrs;
    uint64_t evt;

    if (!(s->cap & RIO_CAP_HPM)) {
        return;
    }

    pthread_rwlock_rdlock(&s->ht_lock);
    value =
        g_hash_table_lookup(s->hpm_event_ctr_map, GUINT_TO_POINTER(event_id));
    if (value == NULL) {
        pthread_rwlock_unlock(&s->ht_lock);
        return;
    }

    for (ctrs = GPOINTER_TO_UINT(value); ctrs != 0; ctrs &= ctrs - 1) {
        ctr_idx = ctz32(ctrs);
        if (get_field(inhibit, BIT(ctr_idx + 1))) {
            continue;
        }

        evt = riscv_iommu_reg_get64(s, RIO_REG_IOHPMEVT_BASE + (ctr_idx << 3));

        /*
         * It's quite possible that event ID has been changed in counter
         * but hashtable hasn't been updated yet. We don't want to increment
         * counter for the old event ID.
         */
        if (event_id != get_field(evt, RIO_IOHPMEVT_MASK_EID)) {
            continue;
        }

        if (get_field(evt, RIO_IOHPMEVT_IDT)) {
            did_gscid = get_field(ctx->gatp, RIO_ATP_MASK_GSCID);
            pid_pscid = get_field(ctx->ta, RIO_PCTA_MASK_PSCID);
        } else {
            did_gscid = ctx->devid;
            pid_pscid = ctx->pasid;
        }

        if (get_field(evt, RIO_IOHPMEVT_PV_PSCV)) {
            /*
             * If the transaction does not have a valid process_id, counter
             * increments if device_id matches DID_GSCID. If the transaction has
             * a valid process_id, counter increments if device_id matches
             * DID_GSCID and process_id matches PID_PSCID. See IOMMU
             * Specification, Chapter 5.23. Performance-monitoring event
             * selector.
             */
            if (ctx->pasid &&
                get_field(evt, RIO_IOHPMEVT_MASK_PID_PSCID) != pid_pscid) {
                continue;
            }
        }

        if (get_field(evt, RIO_IOHPMEVT_DV_GSCV)) {
            uint32_t mask = ~0;

            if (get_field(evt, RIO_IOHPMEVT_DMASK)) {
                /*
                 * 1001 1011   mask = GSCID
                 * 0000 0111   mask = mask ^ (mask + 1)
                 * 1111 1000   mask = ~mask;
                 */
                mask = get_field(evt, RIO_IOHPMEVT_MASK_DID_GSCID);
                mask = mask ^ (mask + 1);
                mask = ~mask;
            }

            if ((get_field(evt, RIO_IOHPMEVT_MASK_DID_GSCID) & mask) !=
                (did_gscid & mask)) {
                continue;
            }
        }

        __hpm_incr_ctr(s, ctr_idx);
    }

    pthread_rwlock_unlock(&s->ht_lock);
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
    bool en_s, en_g;
    struct {
        unsigned char step;
        unsigned char levels;
        unsigned char ptidxbits;
        unsigned char ptesize;
    } sc[2];
    /* Translation stage phase */
    enum {
        S_STAGE = 0,
        G_STAGE = 1,
    } pass;

    satp = get_field(ctx->satp, RIO_ATP_MASK_MODE);
    gatp = get_field(ctx->gatp, RIO_ATP_MASK_MODE);

    en_s = satp != RIO_ATP_MODE_BARE && !gpa;
    en_g = gatp != RIO_ATP_MODE_BARE;

    /* Exit early for pass-through mode. */
    if (!(en_s || en_g)) {
        iotlb->translated_addr = iotlb->iova;
        iotlb->addr_mask = ~TARGET_PAGE_MASK;
        /* Allow R/W in pass-through mode */
        iotlb->perm = IOMMU_RW;
        return 0;
    }

    /* S/G translation parameters. */
    for (pass = 0; pass < 2; pass++) {
        sc[pass].step = 0;
        switch (pass ? gatp : satp) {
        case RIO_ATP_MODE_BARE:
            sc[pass].levels    = 0;
            sc[pass].ptidxbits = 0;
            sc[pass].ptesize   = 0;
            break;
        case RIO_ATP_MODE_SV32:
            if (!(s->cap & (pass ? RIO_CAP_G_SV32 : RIO_CAP_S_SV32))) {
                return RIO_CAUSE_DDT_UNSUPPORTED;
            }
            sc[pass].levels    = 2;
            sc[pass].ptidxbits = 10;
            sc[pass].ptesize   = 4;
            break;
        case RIO_ATP_MODE_SV39:
            if (!(s->cap & (pass ? RIO_CAP_G_SV39 : RIO_CAP_S_SV39))) {
                return RIO_CAUSE_DDT_UNSUPPORTED;
            }
            sc[pass].levels    = 3;
            sc[pass].ptidxbits = 9;
            sc[pass].ptesize   = 8;
            break;
        case RIO_ATP_MODE_SV48:
            if (!(s->cap & (pass ? RIO_CAP_G_SV48 : RIO_CAP_S_SV48))) {
                return RIO_CAUSE_DDT_UNSUPPORTED;
            }
            sc[pass].levels    = 4;
            sc[pass].ptidxbits = 9;
            sc[pass].ptesize   = 8;
            break;
        case RIO_ATP_MODE_SV57:
            if (!(s->cap & (pass ? RIO_CAP_G_SV57 : RIO_CAP_S_SV57))) {
                return RIO_CAUSE_DDT_UNSUPPORTED;
            }
            sc[pass].levels    = 5;
            sc[pass].ptidxbits = 9;
            sc[pass].ptesize   = 8;
            break;
        default:
            return RIO_CAUSE_DDT_UNSUPPORTED;
        }
    };

    /* S/G stages translation tables root pointers */
    gatp = PPN_PHYS(get_field(ctx->gatp, RIO_ATP_MASK_PPN));
    satp = PPN_PHYS(get_field(ctx->satp, RIO_ATP_MASK_PPN));
    addr = (en_s && en_g) ? satp : iotlb->iova;
    base = en_g ? gatp : satp;
    pass = en_g ? G_STAGE : S_STAGE;

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

        if (pass == S_STAGE) {
            riscv_iommu_hpm_incr_ctr(s, ctx, RIO_HPMEVENT_S_VS_WALKS);
        } else {
            riscv_iommu_hpm_incr_ctr(s, ctx, RIO_HPMEVENT_G_WALKS);
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
                pass = S_STAGE;
                addr = iotlb->iova;
                continue;
            }
            /* Translation phase completed (GPA or SPA) */
            iotlb->translated_addr = base;
            iotlb->perm = (pte & PTE_W) ? ((pte & PTE_R) ? IOMMU_RW : IOMMU_WO)
                                                         : IOMMU_RO;
            /* Continue with G-Stage translation? */
            if (!pass && en_g) {
                pass = G_STAGE;
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
            pass = G_STAGE;
            addr = base;
            base = gatp;
            sc[pass].step = 0;
        }
    } while (1);

    return (iotlb->perm & IOMMU_WO) ?
                (pass ? RIO_CAUSE_WR_FAULT_G : RIO_CAUSE_WR_FAULT_S) :
                (pass ? RIO_CAUSE_RD_FAULT_G : RIO_CAUSE_RD_FAULT_S);
}

/* Portable implementation of pext_u64, bit-mask extraction. */
static uint64_t _pext_u64(uint64_t val, uint64_t ext)
{
    uint64_t ret = 0;
    uint64_t rot = 1;

    while (ext) {
        if (ext & 1) {
            if (val & 1) {
                ret |= rot;
            }
            rot <<= 1;
        }
        val >>= 1;
        ext >>= 1;
    }

    return ret;
}

/* Check if IOVA matches MSI/MRIF pattern. */
static bool riscv_iommu_msi_check(RISCVIOMMUState *s, RISCVIOMMUContext *ctx,
        dma_addr_t iova)
{
    if (get_field(ctx->msi_redirect, RIO_DCMSI_MASK_MODE) !=
        RIO_DCMSI_MODE_FLAT) {
        return false; /* Invalid MSI/MRIF mode */
    }

    if ((PPN_DOWN(iova) ^ ctx->msi_addr_pattern) & ~ctx->msi_addr_mask) {
        return false; /* IOVA not in MSI range defined by AIA IMSIC rules. */
    }

    return true;
}

/* Redirect MSI write for given IOVA. */
static MemTxResult riscv_iommu_msi_write(RISCVIOMMUState *s,
        RISCVIOMMUContext *ctx, uint64_t iova, uint64_t data,
        unsigned size, MemTxAttrs attrs)
{
    MemTxResult res;
    dma_addr_t addr;
    uint64_t intn;
    uint32_t n190;
    uint64_t pte[2];

    if (!riscv_iommu_msi_check(s, ctx, iova)) {
        return MEMTX_ACCESS_ERROR;
    }

    /* Interrupt File Number */
    intn = _pext_u64(PPN_DOWN(iova), ctx->msi_addr_mask);
    if (intn >= 256) {
        /* Interrupt file number out of range */
        return MEMTX_ACCESS_ERROR;
    }

    /* fetch MSI PTE */
    addr = PPN_PHYS(get_field(ctx->msi_redirect, RIO_DCMSI_MASK_PPN));
    addr = addr | (intn * sizeof(pte));
    res = dma_memory_read(s->target_as, addr, &pte, sizeof(pte),
            MEMTXATTRS_UNSPECIFIED);
    if (res != MEMTX_OK) {
        return res;
    }

    le64_to_cpus(&pte[0]);
    le64_to_cpus(&pte[1]);

    if (!(pte[0] & RIO_MSIPTE_V) || (pte[0] & RIO_MSIPTE_C)) {
        return MEMTX_ACCESS_ERROR;
    }

    if (pte[0] & RIO_MSIPTE_W) {
        /* MSI Pass-through mode */
        addr = PPN_PHYS(get_field(pte[0], RIO_MSIPTE_MASK_PPN));
        addr = addr | (iova & TARGET_PAGE_MASK);
        return dma_memory_write(s->target_as, addr, &data, size, attrs);
    }

    /*
     * Report an error for interrupt identities exceeding the maximum allowed
     * for an IMSIC interrupt file (2047) or destination addres is not 32-bit
     * aligned. See IOMMU Specification, Chapter 2.3. MSI page tables.
     */
    if ((data > 2047) || (iova & 3)) {
        return MEMTX_ACCESS_ERROR;
    }

    /* MSI MRIF mode, non atomic pending bit update */

    /* MRIF pending bit address */
    addr = get_field(pte[0], RIO_MRIF_ADDR_MASK_PPN) << 9;
    addr = addr | ((data & 0x7c0) >> 3);
    /* MRIF pending bit mask */
    data = 1ULL << (data & 0x03f);
    res = dma_memory_read(s->target_as, addr, &intn, sizeof(intn), attrs);
    if (res != MEMTX_OK) {
        return res;
    }
    intn = intn | data;
    res = dma_memory_write(s->target_as, addr, &intn, sizeof(intn), attrs);
    if (res != MEMTX_OK) {
        return res;
    }

    /* Get MRIF enable bits */
    addr = addr + sizeof(intn);
    res = dma_memory_read(s->target_as, addr, &intn, sizeof(intn), attrs);
    if (res != MEMTX_OK) {
        return res;
    }
    if (!(intn & data)) {
        /* notification disabled, MRIF update completed. */
        return MEMTX_OK;
    }

    /* Send notification message */
    addr = PPN_PHYS(get_field(pte[1], RIO_MRIF_NPPN_MASK_PPN));
    n190 = get_field(pte[1], RIO_MRIF_NPPN_MASK_N90) |
          (get_field(pte[1], RIO_MRIF_NPPN_MASK_N10) << 10);

    res = dma_memory_write(s->target_as, addr, &n190, sizeof(n190), attrs);
    if (res != MEMTX_OK) {
        return res;
    }

    return MEMTX_OK;
}

/*
 * RISC-V IOMMU Device Context Loopkup - Device Directory Tree Walk
 *
 * @s         : IOMMU Device State
 * @ctx       : Device Translation Context with devid and pasid set.
 * @return    : success or fault code.
 */
static int riscv_iommu_ctx_fetch(RISCVIOMMUState *s, RISCVIOMMUContext *ctx)
{
    const uint64_t ddtp = s->ddtp;
    unsigned mode = get_field(ddtp, RIO_DDTP_MASK_MODE);
    dma_addr_t addr = PPN_PHYS(get_field(ddtp, RIO_DDTP_MASK_PPN));
    /* Device Context format: 0: extended (64 bytes) | 1: base (32 bytes) */
    const int dc_fmt = !s->enable_msi;
    const size_t dc_len = sizeof(RISCVIOMMUDeviceContext) >> dc_fmt;
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
        ctx->msi_redirect = 0;
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

    /*
     * Check supported device id width (in bits).
     * See IOMMU Specification, Chapter 6. Software guidelines.
     * - if extended device-context format is used:
     *   1LVL: 6, 2LVL: 15, 3LVL: 24
     * - if base device-context format is used:
     *   1LVL: 7, 2LVL: 16, 3LVL: 24
     */
    if (ctx->devid >= (1 << (depth * 9 + 6 + (dc_fmt && depth != 2)))) {
        return RIO_CAUSE_DDT_INVALID;
    }

    /* Device directory tree walk */
    for (; depth-- > 0; ) {
        riscv_iommu_hpm_incr_ctr(s, ctx, RIO_HPMEVENT_DD_WALK);

        /*
         * Select device id index bits based on device directory tree level
         * and device context format.
         * See IOMMU Specification, Chapter 2. Data Structures.
         * - if extended device-context format is used:
         *   device index: [23:15][14:6][5:0]
         * - if base device-context format is used:
         *   device index: [23:16][15:7][6:0]
         */
        const int split = depth * 9 + 6 + dc_fmt;
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

    riscv_iommu_hpm_incr_ctr(s, ctx, RIO_HPMEVENT_DD_WALK);

    /* index into device context entry page */
    addr |= (ctx->devid * dc_len) & ~TARGET_PAGE_MASK;

    memset(&dc, 0, sizeof(dc));
    if (dma_memory_read(s->target_as, addr, &dc, dc_len,
                        MEMTXATTRS_UNSPECIFIED) != MEMTX_OK) {
        return RIO_CAUSE_DDT_FAULT;
    }

    /* Set translation context. */
    ctx->tc = le64_to_cpu(dc.tc);
    ctx->gatp = le64_to_cpu(dc.gatp);
    ctx->satp = le64_to_cpu(dc.fsc);
    ctx->ta = le64_to_cpu(dc.ta);
    ctx->msi_redirect = le64_to_cpu(dc.msiptp);
    ctx->msi_addr_mask = le64_to_cpu(dc.msi_addr_mask);
    ctx->msi_addr_pattern = le64_to_cpu(dc.msi_addr_pattern);

    if (!(ctx->tc & RIO_DCTC_VALID)) {
        return RIO_CAUSE_DDT_INVALID;
    }

    /* FSC field checks */
    mode = get_field(ctx->satp, RIO_ATP_MASK_MODE);
    addr = PPN_PHYS(get_field(ctx->satp, RIO_ATP_MASK_PPN));

    if (mode == RIO_PDTP_MODE_BARE) {
        return 0;                       /* No S-Stage translation */
    }

    if (!(ctx->tc & RIO_DCTC_PDTV)) {
        if (ctx->pasid) {
            return RIO_CAUSE_REQ_INVALID; /* PASID is disabled */
        }
        if (mode > RIO_ATP_MODE_SV57) {
            return RIO_CAUSE_DDT_INVALID; /* Invalid SATP.MODE */
        }
        return 0;
    }

    /* FSC.TC.PDTV enabled */
    if (mode > RIO_PDTP_MODE_PD8) {
        return RIO_CAUSE_PDT_UNSUPPORTED; /* Invalid PDTP.MODE */
    }

    for (depth = RIO_PDTP_MODE_PD8 - mode; depth-- > 0; ) {
        riscv_iommu_hpm_incr_ctr(s, ctx, RIO_HPMEVENT_PD_WALK);

        /*
         * Select process id index bits based on process directory tree
         * level. See IOMMU Specification, 2.2. Process-Directory-Table.
         */
        const int split = depth * 9 + 8;
        addr |= ((ctx->pasid >> split) << 3) & ~TARGET_PAGE_MASK;
        if (dma_memory_read(s->target_as, addr, &de, sizeof(de),
                            MEMTXATTRS_UNSPECIFIED) != MEMTX_OK) {
            return RIO_CAUSE_PDT_FAULT;
        }
        le64_to_cpus(&de);
        if (!(de & RIO_PDTE_VALID)) {
            return RIO_CAUSE_PDT_INVALID;
        }
        addr = PPN_PHYS(get_field(de, RIO_PDTE_MASK_PPN));
    }

    riscv_iommu_hpm_incr_ctr(s, ctx, RIO_HPMEVENT_PD_WALK);

    /* Leaf entry in PDT */
    addr |= (ctx->pasid << 4) & ~TARGET_PAGE_MASK;
    if (dma_memory_read(s->target_as, addr, &dc.ta, sizeof(uint64_t) * 2,
                        MEMTXATTRS_UNSPECIFIED) != MEMTX_OK) {
        return RIO_CAUSE_PDT_FAULT;
    }

    /* Use FSC and TA from process directory entry. */
    ctx->ta = le64_to_cpu(dc.ta);
    ctx->satp = le64_to_cpu(dc.fsc);

    if (!(ctx->ta & RIO_PCTA_V)) {
        return RIO_CAUSE_PDT_INVALID;
    }

    return 0;
}

/* Translation Context cache support */
static gboolean __ctx_equal(gconstpointer v1, gconstpointer v2)
{
    RISCVIOMMUContext *c1 = (RISCVIOMMUContext *) v1;
    RISCVIOMMUContext *c2 = (RISCVIOMMUContext *) v2;
    return c1->devid == c2->devid && c1->pasid == c2->pasid;
}

static guint __ctx_hash(gconstpointer v)
{
    RISCVIOMMUContext *ctx = (RISCVIOMMUContext *) v;
    /* Generate simple hash of (pasid, devid), assuming 24-bit wide devid */
    return (guint)(ctx->devid) + ((guint)(ctx->pasid) << 24);
}

static void __ctx_inval_pasid(gpointer key, gpointer value, gpointer data)
{
    RISCVIOMMUContext *ctx = (RISCVIOMMUContext *) value;
    RISCVIOMMUContext *arg = (RISCVIOMMUContext *) data;
    if ((ctx->tc & RIO_DCTC_VALID) &&
        (ctx->devid == arg->devid) && (ctx->pasid == arg->pasid)) {
        ctx->tc &= ~RIO_DCTC_VALID;
    }
}

static void __ctx_inval_devid(gpointer key, gpointer value, gpointer data)
{
    RISCVIOMMUContext *ctx = (RISCVIOMMUContext *) value;
    RISCVIOMMUContext *arg = (RISCVIOMMUContext *) data;
    if ((ctx->tc & RIO_DCTC_VALID) &&
        (ctx->devid == arg->devid)) {
        ctx->tc &= ~RIO_DCTC_VALID;
    }
}

static void __ctx_inval_any(gpointer key, gpointer value, gpointer data)
{
    RISCVIOMMUContext *ctx = (RISCVIOMMUContext *) value;
    if (ctx->tc & RIO_DCTC_VALID) {
        ctx->tc &= ~RIO_DCTC_VALID;
    }
}

static void riscv_iommu_ctx_inval(RISCVIOMMUState *s, GHFunc func,
        uint32_t devid, uint32_t pasid)
{
    GHashTable *ctx_cache;
    RISCVIOMMUContext key = {
        .devid = devid,
        .pasid = pasid,
    };
    ctx_cache = g_hash_table_ref(s->ctx_cache);
    g_hash_table_foreach(ctx_cache, func, &key);
    g_hash_table_unref(ctx_cache);
}

/* Find or allocate translation context for a given {device_id, process_id} */
static RISCVIOMMUContext *riscv_iommu_ctx(RISCVIOMMUState *s,
        unsigned devid, unsigned pasid, void **ref)
{
    GHashTable *ctx_cache;
    RISCVIOMMUContext *ctx;
    RISCVIOMMUContext key = {
        .devid = devid,
        .pasid = pasid,
    };

    ctx_cache = g_hash_table_ref(s->ctx_cache);
    ctx = g_hash_table_lookup(ctx_cache, &key);

    if (ctx && (ctx->tc & RIO_DCTC_VALID)) {
        *ref = ctx_cache;
        return ctx;
    }

    if (g_hash_table_size(s->ctx_cache) >= LIMIT_CACHE_CTX) {
        ctx_cache = g_hash_table_new_full(__ctx_hash, __ctx_equal,
                                          g_free, NULL);
        g_hash_table_unref(qatomic_xchg(&s->ctx_cache, ctx_cache));
    }

    ctx = g_new0(RISCVIOMMUContext, 1);
    ctx->devid = devid;
    ctx->pasid = pasid;

    int fault = riscv_iommu_ctx_fetch(s, ctx);
    if (!fault) {
        g_hash_table_add(ctx_cache, ctx);
        *ref = ctx_cache;
        return ctx;
    }

    g_hash_table_unref(ctx_cache);
    *ref = NULL;

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
        g_hash_table_unref((GHashTable *)ref);
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

/* Translation Object cache support */
static gboolean __iot_equal(gconstpointer v1, gconstpointer v2)
{
    RISCVIOMMUEntry *t1 = (RISCVIOMMUEntry *) v1;
    RISCVIOMMUEntry *t2 = (RISCVIOMMUEntry *) v2;
    return t1->gscid == t2->gscid && t1->pscid == t2->pscid &&
           t1->iova == t2->iova;
}

static guint __iot_hash(gconstpointer v)
{
    RISCVIOMMUEntry *t = (RISCVIOMMUEntry *) v;
    return (guint)t->iova;
}

/* GV: 1 PSCV: 1 AV: 1 */
static void __iot_inval_iova(gpointer key, gpointer value, gpointer data)
{
    RISCVIOMMUEntry *iot = (RISCVIOMMUEntry *) value;
    RISCVIOMMUEntry *arg = (RISCVIOMMUEntry *) data;
    if (iot->gscid == arg->gscid && iot->pscid == arg->pscid &&
        iot->iova == arg->iova) {
        iot->perm = 0;
    }
}

/* GV: 1 PSCV: 1 AV: X */
static void __iot_inval_pscid(gpointer key, gpointer value, gpointer data)
{
    RISCVIOMMUEntry *iot = (RISCVIOMMUEntry *) value;
    RISCVIOMMUEntry *arg = (RISCVIOMMUEntry *) data;
    if (iot->gscid == arg->gscid && iot->pscid == arg->pscid) {
        iot->perm = 0;
    }
}

/* GV: 1 PSCV: X AV: X */
static void __iot_inval_gscid(gpointer key, gpointer value, gpointer data)
{
    RISCVIOMMUEntry *iot = (RISCVIOMMUEntry *) value;
    RISCVIOMMUEntry *arg = (RISCVIOMMUEntry *) data;
    if (iot->gscid == arg->gscid) {
        iot->perm = 0;
    }
}

/* caller should keep ref-count for iot_cache object */
static RISCVIOMMUEntry *riscv_iommu_iot_lookup(RISCVIOMMUContext *ctx,
        GHashTable *iot_cache, hwaddr iova)
{
    RISCVIOMMUEntry key = {
        .gscid = get_field(ctx->gatp, RIO_ATP_MASK_GSCID),
        .pscid = get_field(ctx->ta, RIO_PCTA_MASK_PSCID),
        .iova  = PPN_DOWN(iova),
    };
    return g_hash_table_lookup(iot_cache, &key);
}

/* caller should keep ref-count for iot_cache object */
static void riscv_iommu_iot_update(RISCVIOMMUState *s,
        GHashTable *iot_cache, RISCVIOMMUEntry *iot)
{
    if (g_hash_table_size(s->iot_cache) >= LIMIT_CACHE_IOT) {
        iot_cache = g_hash_table_new_full(__iot_hash, __iot_equal,
                                          g_free, NULL);
        g_hash_table_unref(qatomic_xchg(&s->iot_cache, iot_cache));
    }
    g_hash_table_add(iot_cache, iot);
}

static void riscv_iommu_iot_inval(RISCVIOMMUState *s, GHFunc func,
        uint32_t gscid, uint32_t pscid, hwaddr iova)
{
    GHashTable *iot_cache;
    RISCVIOMMUEntry key = {
        .gscid = gscid,
        .pscid = pscid,
        .iova  = PPN_DOWN(iova),
    };

    if (func == NULL) {
        iot_cache = g_hash_table_new_full(__iot_hash, __iot_equal,
                                          g_free, NULL);
        g_hash_table_unref(qatomic_xchg(&s->iot_cache, iot_cache));
    } else {
        iot_cache = g_hash_table_ref(s->iot_cache);
        g_hash_table_foreach(iot_cache, func, &key);
        g_hash_table_unref(iot_cache);
    }
}

static int riscv_iommu_translate(RISCVIOMMUState *s, RISCVIOMMUContext *ctx,
        IOMMUTLBEntry *iotlb)
{
    RISCVIOMMUEntry *iot;
    IOMMUAccessFlags perm;
    bool enable_faults = true;
    bool enable_pasid = false;
    GHashTable *iot_cache;
    int fault;

    if ((iotlb->perm & IOMMU_WO) &&
            riscv_iommu_msi_check(s, ctx, iotlb->iova)) {
        /* Trap MSI writes and return untranslated address. */
        iotlb->target_as = &s->trap_as;
        iotlb->translated_addr = iotlb->iova;
        iotlb->addr_mask = ~TARGET_PAGE_MASK;
        return 0;
    }

    riscv_iommu_hpm_incr_ctr(s, ctx, RIO_HPMEVENT_URQ);

    iot_cache = g_hash_table_ref(s->iot_cache);

    enable_faults = !(ctx->tc & RIO_DCTC_DTF);
    enable_pasid = (ctx->tc & RIO_DCTC_PDTV) && (ctx->ta & RIO_PCTA_V);

    /* Check for ATS request. */
    if (iotlb->perm == IOMMU_NONE) {
        riscv_iommu_hpm_incr_ctr(s, ctx, RIO_HPMEVENT_ATS_RQ);
        /* Check if ATS is disabled. */
        if (!(ctx->tc & RIO_DCTC_EN_ATS)) {
            fault = RIO_CAUSE_REQ_INVALID;
            goto done;
        }
    }

    iot = riscv_iommu_iot_lookup(ctx, iot_cache, iotlb->iova);
    perm = iot ? iot->perm : IOMMU_NONE;
    if (perm != IOMMU_NONE) {
        iotlb->translated_addr = PPN_PHYS(iot->phys);
        iotlb->addr_mask = ~TARGET_PAGE_MASK;
        iotlb->perm = perm;
        fault = 0;
        goto done;
    }

    riscv_iommu_hpm_incr_ctr(s, ctx, RIO_HPMEVENT_TLB_MISS);

    /* Translate using device directory / page table information. */
    fault = riscv_iommu_spa_fetch(s, ctx, iotlb, false);

    if (!fault && (ctx->ta & RIO_PCTA_V) &&
        (iotlb->translated_addr != iotlb->iova)) {
        iot = g_new0(RISCVIOMMUEntry, 1);
        iot->iova = PPN_DOWN(iotlb->iova);
        iot->phys = PPN_DOWN(iotlb->translated_addr);
        iot->gscid = get_field(ctx->gatp, RIO_ATP_MASK_GSCID);
        iot->pscid = get_field(ctx->ta, RIO_PCTA_MASK_PSCID);
        iot->perm = iotlb->perm;
        riscv_iommu_iot_update(s, iot_cache, iot);
    }

done:
    g_hash_table_unref(iot_cache);

    if (enable_faults && fault) {
        RISCVIOMMUEvent ev;
        const unsigned ttype = (iotlb->perm & IOMMU_RW) ? RIO_TTYP_UWR :
                ((iotlb->perm & IOMMU_RO) ? RIO_TTYP_URD : RIO_TTYP_ATS);
        ev.reason = set_field(ctx->devid, RIO_EVENT_MASK_CAUSE, fault);
        ev.reason = set_field(ev.reason, RIO_EVENT_MASK_TTYPE, ttype);
        ev.reason = set_field(ev.reason, RIO_EVENT_PV, enable_pasid);
        ev.reason = set_field(ev.reason, RIO_EVENT_MASK_PID, ctx->pasid);
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

    riscv_iommu_reg_set64(s, RIO_REG_DDTP, new_ddtp);
}

static void riscv_iommu_process_cq_tail(RISCVIOMMUState *s)
{
    RISCVIOMMUCommand cmd;
    MemTxResult res;
    dma_addr_t addr;
    uint32_t tail, head, ctrl;
    GHFunc func;

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
            if (cmd.request & RIO_IOTINVAL_MSI) {
                /* MSI cache not implemented */
                break;
            }
            do {
                func = NULL;
                if (!(cmd.request & RIO_IOTINVAL_GSCID_VALID)) {
                    break;
                }
                func = __iot_inval_gscid;
                if (cmd.request & RIO_IOTINVAL_GSTAGE) {
                    break;
                }
                if (!(cmd.request & RIO_IOTINVAL_PSCID_VALID)) {
                    break;
                }
                func = __iot_inval_pscid;
                if (!(cmd.request & RIO_IOTINVAL_ADDR_VALID)) {
                    break;
                }
                func = __iot_inval_iova;
            } while (0) ;

            riscv_iommu_iot_inval(s, func,
                    get_field(cmd.request, RIO_IOTINVAL_MASK_GSCID),
                    get_field(cmd.request, RIO_IOTINVAL_MASK_PSCID),
                    cmd.address & TARGET_PAGE_MASK);
            break;

        case RIO_CMD_IODIR:
            if (!(cmd.request & RIO_IODIR_DID_VALID)) {
                func = __ctx_inval_any;
            } else if (cmd.request & RIO_IODIR_PID_VALID) {
                func = __ctx_inval_pasid;
            } else {
                func = __ctx_inval_devid;
            }
            riscv_iommu_ctx_inval(s, func,
                    get_field(cmd.request, RIO_IODIR_MASK_DID),
                    get_field(cmd.request, RIO_IODIR_MASK_PID));
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
    unsigned devid = get_field(ctrl, RIO_TRREQ_MASK_DID);
    unsigned pid = get_field(ctrl, RIO_TRREQ_MASK_PID);
    RISCVIOMMUContext *ctx;
    void *ref;

    if (!(ctrl & RIO_TRREQ_BUSY)) {
        return;
    }

    ctx = riscv_iommu_ctx(s, devid, pid, &ref);
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
    RIO_EXEC_EXIT,  /* RIO_EXEC_EXIT must be the last enum value */
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

/* For now we assume IOMMU HPM frequency to be 1GHz so 1-cycle is of 1-ns. */
static inline uint64_t __get_cycles(void)
{
    return qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
}

static void __hpm_setup_timer(RISCVIOMMUState *s, uint64_t value)
{
    const uint32_t inhibit = riscv_iommu_reg_get32(s, RIO_REG_IOCNTINH);
    uint64_t overflow_at, overflow_ns;

    if (get_field(inhibit, RIO_IOCNTINH_CY)) {
        return;
    }

    /*
     * We are using INT64_MAX here instead to UINT64_MAX because cycle counter
     * has 63-bit precision and INT64_MAX is the maximum it can store.
     */
    if (value) {
        overflow_ns = INT64_MAX - value + 1;
    } else {
        overflow_ns = INT64_MAX;
    }

    overflow_at = (uint64_t)qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + overflow_ns;

    if (overflow_at > INT64_MAX) {
        s->irq_overflow_left = overflow_at - INT64_MAX;
        overflow_at = INT64_MAX;
    }

    timer_mod_anticipate_ns(s->hpm_timer, overflow_at);
}

/* Updates the internal cycle counter state when iocntinh:CY is changed. */
static void riscv_iommu_process_iocntinh_cy(RISCVIOMMUState *s,
                                            bool prev_cy_inh)
{
    const uint32_t inhibit = riscv_iommu_reg_get32(s, RIO_REG_IOCNTINH);

    /* We only need to process CY bit toggle. */
    if (!(inhibit ^ prev_cy_inh)) {
        return;
    }

    if (!(inhibit & RIO_IOCNTINH_CY)) {
        /*
         * Cycle counter is enabled. Just start the timer again and update the
         * clock snapshot value to point to the current time to make sure
         * iohpmcycles read is correct.
         */
        s->hpmcycle_prev = __get_cycles();
        __hpm_setup_timer(s, s->hpmcycle_val);
    } else {
        /*
         * Cycle counter is disabled. Stop the timer and update the cycle
         * counter to record the current value which is last programmed
         * value + the cycles passed so far.
         */
        s->hpmcycle_val = s->hpmcycle_val + (__get_cycles() - s->hpmcycle_prev);
        timer_del(s->hpm_timer);
    }
}

static void riscv_iommu_process_hpmcycle_write(RISCVIOMMUState *s)
{
    const uint64_t val = riscv_iommu_reg_get64(s, RIO_REG_IOHPMCYCLES);
    const uint32_t ovf = riscv_iommu_reg_get32(s, RIO_REG_IOCNTOVF);

    /*
     * Clear OF bit in IOCNTOVF if it's being cleared in IOHPMCYCLES register.
     */
    if (get_field(ovf, RIO_IOCNTOVF_CY) &&
        !get_field(val, RIO_IOHPMCYCLES_OF)) {
        riscv_iommu_reg_mod32(s, RIO_REG_IOCNTOVF, 0, RIO_IOCNTOVF_CY);
    }

    s->hpmcycle_val = val & ~RIO_IOHPMCYCLES_OF;
    s->hpmcycle_prev = __get_cycles();
    __hpm_setup_timer(s, s->hpmcycle_val);
}

static inline bool __check_valid_event_id(enum RISCVIOMMUEventID event_id)
{
    return event_id > RIO_HPMEVENT_INVALID && event_id < RIO_HPMEVENT_MAX;
}

static gboolean __hpm_event_equal(gpointer key, gpointer value, gpointer udata)
{
    uint32_t *pair = udata;

    if (GPOINTER_TO_UINT(value) & (1 << pair[0])) {
        pair[1] = GPOINTER_TO_UINT(key);
        return true;
    }

    return false;
}

/* Caller must check ctr_idx against hpm_ctrs to see if its supported or not. */
static void
__update_event_map(RISCVIOMMUState *s, uint64_t value, uint32_t ctr_idx)
{
    enum RISCVIOMMUEventID event_id = get_field(value, RIO_IOHPMEVT_MASK_EID);
    uint32_t pair[2] = { ctr_idx, RIO_HPMEVENT_INVALID };
    uint32_t new_value = 1 << ctr_idx;
    gpointer data;

    /* If EventID field is RIO_HPMEVENT_INVALID remove the current mapping. */
    if (event_id == RIO_HPMEVENT_INVALID) {
        data = g_hash_table_find(s->hpm_event_ctr_map, __hpm_event_equal, pair);

        new_value = GPOINTER_TO_UINT(data) & ~(new_value);
        pthread_rwlock_wrlock(&s->ht_lock);
        if (new_value != 0) {
            g_hash_table_replace(s->hpm_event_ctr_map,
                                 GUINT_TO_POINTER(pair[1]),
                                 GUINT_TO_POINTER(new_value));
        } else {
            g_hash_table_remove(s->hpm_event_ctr_map,
                                GUINT_TO_POINTER(pair[1]));
        }
        pthread_rwlock_unlock(&s->ht_lock);

        return;
    }

    /* Update the counter mask if the event is already enabled. */
    if (g_hash_table_lookup_extended(s->hpm_event_ctr_map,
                                     GUINT_TO_POINTER(event_id),
                                     NULL,
                                     &data)) {
        new_value |= GPOINTER_TO_UINT(data);
    }

    pthread_rwlock_wrlock(&s->ht_lock);
    g_hash_table_insert(s->hpm_event_ctr_map,
                        GUINT_TO_POINTER(event_id),
                        GUINT_TO_POINTER(new_value));
    pthread_rwlock_unlock(&s->ht_lock);
}

static void riscv_iommu_process_hpmevt_write(RISCVIOMMUState *s,
                                             uint32_t evt_reg)
{
    const uint32_t ctr_idx = (evt_reg - RIO_REG_IOHPMEVT_BASE) >> 3;
    const uint32_t ovf = riscv_iommu_reg_get32(s, RIO_REG_IOCNTOVF);
    uint64_t val = riscv_iommu_reg_get64(s, evt_reg);

    if (ctr_idx >= s->hpm_cntrs) {
        return;
    }

    /* Clear OF bit in IOCNTOVF if it's being cleared in IOHPMEVT register. */
    if (get_field(ovf, BIT(ctr_idx + 1)) && !get_field(val, RIO_IOHPMEVT_OF)) {
        /* +1 to offset CYCLE register OF bit. */
        riscv_iommu_reg_mod32(s, RIO_REG_IOCNTOVF, 0, BIT(ctr_idx + 1));
    }

    if (!__check_valid_event_id(get_field(val, RIO_IOHPMEVT_MASK_EID))) {
        /* Reset EventID (WARL) field to invalid. */
        val = set_field(val, RIO_IOHPMEVT_MASK_EID, RIO_HPMEVENT_INVALID);
        riscv_iommu_reg_set64(s, evt_reg, val);
    }

    __update_event_map(s, val, ctr_idx);
}

static void riscv_iommu_process_hpm_writes(RISCVIOMMUState *s,
                                           uint32_t regb,
                                           bool prev_cy_inh)
{
    switch (regb) {
    case RIO_REG_IOCNTINH:
        riscv_iommu_process_iocntinh_cy(s, prev_cy_inh);
        break;

    case RIO_REG_IOHPMCYCLES:
    case RIO_REG_IOHPMCYCLES + 4:
        riscv_iommu_process_hpmcycle_write(s);
        break;

    case RIO_REG_IOHPMEVT_BASE ... RIO_REG_IOHPMEVT_END + 4:
        riscv_iommu_process_hpmevt_write(s, regb & ~7);
        break;
    }
}

static MemTxResult riscv_iommu_mmio_write(void *opaque, hwaddr addr,
        uint64_t data, unsigned size, MemTxAttrs attrs)
{
    RISCVIOMMUState *s = opaque;
    uint32_t regb = addr & ~3;
    bool cy_inh = false;
    uint32_t busy = 0;
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

    case RIO_REG_IOCNTINH:
        if (addr != RIO_REG_IOCNTINH) {
            break;
        }

        /* Store previous value of CY bit. */
        cy_inh =
            !!(riscv_iommu_reg_get32(s, RIO_REG_IOCNTINH) & RIO_IOCNTINH_CY);
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

    /* Process HPM writes and update any internal state if needed. */
    if (regb >= RIO_REG_IOCNTOVF && regb <= (RIO_REG_IOHPMEVT_END + 4)) {
        riscv_iommu_process_hpm_writes(s, regb, cy_inh);
    }

    /* Wakeup core processing thread. */
    if (exec) {
        qemu_mutex_lock(&s->core_lock);
        s->core_exec |= exec;
        qemu_cond_signal(&s->core_cond);
        qemu_mutex_unlock(&s->core_lock);
    }

    return MEMTX_OK;
}

static uint64_t riscv_iommu_hpmcycle_read(RISCVIOMMUState *s)
{
    const uint64_t cycle = riscv_iommu_reg_get64(s, RIO_REG_IOHPMCYCLES);
    const uint32_t inhibit = riscv_iommu_reg_get32(s, RIO_REG_IOCNTINH);
    const uint64_t ctr_prev = s->hpmcycle_prev;
    const uint64_t ctr_val = s->hpmcycle_val;

    if (get_field(inhibit, RIO_IOCNTINH_CY)) {
        /*
         * Counter should not increment if inhibit bit is set. We can't really
         * stop the QEMU_CLOCK_VIRTUAL, so we just return the last updated
         * counter value to indicate that counter was not incremented.
         */
        return (ctr_val & RIO_IOHPMCYCLES_MASK_CNTR) |
               (cycle & RIO_IOHPMCYCLES_OF);
    }

    return (ctr_val + __get_cycles() - ctr_prev) | (cycle & RIO_IOHPMCYCLES_OF);
}

static MemTxResult riscv_iommu_mmio_read(void *opaque, hwaddr addr,
        uint64_t *data, unsigned size, MemTxAttrs attrs)
{
    RISCVIOMMUState *s = opaque;
    uint64_t val = -1;
    uint8_t *ptr;

    if ((addr & (size - 1)) != 0) {
        /* Unsupported MMIO alignment. */
        return MEMTX_ERROR;
    }

    if (addr + size > sizeof(s->regs_rw)) {
        return MEMTX_ACCESS_ERROR;
    }

    /* Compute cycle register value. */
    if ((addr & ~7) == RIO_REG_IOHPMCYCLES) {
        val = riscv_iommu_hpmcycle_read(s);
        ptr = (uint8_t *)&val + (addr & 7);
    } else {
        ptr = &s->regs_rw[addr];
    }

    if (size == 1) {
        val = (uint64_t)*ptr;
    } else if (size == 2) {
        val = lduw_le_p(ptr);
    } else if (size == 4) {
        val = ldl_le_p(ptr);
    } else if (size == 8) {
        val = ldq_le_p(ptr);
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

/*
 * Translations matching MSI pattern check are redirected to "riscv-iommu-trap"
 * memory region as untranslated address, for additional MSI/MRIF interception
 * by IOMMU interrupt remapping implementation.
 * Note: Device emulation code generating an MSI is expected to provide a valid
 * memory transaction attributes with requested_id set.
 */
static MemTxResult riscv_iommu_trap_write(void *opaque, hwaddr addr,
        uint64_t data, unsigned size, MemTxAttrs attrs)
{
    RISCVIOMMUState* s = (RISCVIOMMUState *)opaque;
    RISCVIOMMUContext *ctx;
    MemTxResult res;
    void *ref;
    uint32_t devid = attrs.requester_id;

    if (attrs.unspecified) {
        return MEMTX_ACCESS_ERROR;
    }

    ctx = riscv_iommu_ctx(s, devid, 0, &ref);
    if (ctx == NULL) {
        res = MEMTX_ACCESS_ERROR;
    } else {
        res = riscv_iommu_msi_write(s, ctx, addr, data, size, attrs);
    }
    riscv_iommu_ctx_put(s, ref);
    return res;
}

static MemTxResult riscv_iommu_trap_read(void *opaque, hwaddr addr,
        uint64_t *data, unsigned size, MemTxAttrs attrs)
{
    return MEMTX_ACCESS_ERROR;
}

static const MemoryRegionOps riscv_iommu_trap_ops = {
    .read_with_attrs = riscv_iommu_trap_read,
    .write_with_attrs = riscv_iommu_trap_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 1,
        .max_access_size = 8,
        .unaligned = true,
    },
    .valid = {
        .min_access_size = 1,
        .max_access_size = 8,
    }
};

/* Timer callback for cycle counter overflow. */
static void riscv_iommu_hpm_timer_cb(void *priv)
{
    RISCVIOMMUState *s = priv;
    const uint32_t inhibit = riscv_iommu_reg_get32(s, RIO_REG_IOCNTINH);
    uint32_t ovf;

    if (get_field(inhibit, RIO_IOCNTINH_CY)) {
        return;
    }

    if (s->irq_overflow_left > 0) {
        uint64_t irq_trigger_at =
            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + s->irq_overflow_left;
        timer_mod_anticipate_ns(s->hpm_timer, irq_trigger_at);
        s->irq_overflow_left = 0;
        return;
    }

    ovf = riscv_iommu_reg_get32(s, RIO_REG_IOCNTOVF);
    if (!get_field(ovf, RIO_IOCNTOVF_CY)) {
        /*
         * We don't need to set hpmcycle_val to zero and update hpmcycle_prev to
         * current clock value. The way we calculate iohpmcycs will overflow
         * and return the correct value. This avoids the need to synchronize
         * timer callback and write callback.
         */
        riscv_iommu_reg_mod32(s, RIO_REG_IOCNTOVF, RIO_IOCNTOVF_CY, 0);
        riscv_iommu_reg_mod64(s, RIO_REG_IOHPMCYCLES, RIO_IOHPMCYCLES_OF, 0);
        riscv_iommu_irq_assert(s, RIO_INT_PM);
    }
}

static void riscv_iommu_init(RISCVIOMMUState *s)
{
    s->cap = s->version & RIO_CAP_REV_MASK;
    if (s->enable_msi) {
        s->cap |= RIO_CAP_MSI_FLAT | RIO_CAP_MSI_MRIF;
    }
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
    if (s->hpm_cntrs > 0) {
        /* Clip number of HPM counters to maximum supported (31). */
        if (s->hpm_cntrs > RIO_IOHPMCTR_NUM_REGS) {
            s->hpm_cntrs = RIO_IOHPMCTR_NUM_REGS;
        }
        /* Enable hardware performance monitor interface */
        s->cap |= RIO_CAP_HPM;
    }
    /* Enable translation debug interface */
    s->cap |= RIO_CAP_DBG;

    /* Report QEMU target physical address space limits */
    s->cap = set_field(s->cap, RIO_CAP_PAS_MASK, TARGET_PHYS_ADDR_SPACE_BITS);

    /* TODO: method to report supported PASID bits */
    s->pasid_bits = 8; /* restricted to size of MemTxAttrs.pasid */

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
    /* If HPM registers are enabled. */
    if (s->cap & RIO_CAP_HPM) {
        /* +1 for cycle counter bit. */
        stl_le_p(&s->regs_ro[RIO_REG_IOCNTINH],
                 ~MAKE_32BIT_MASK(0, s->hpm_cntrs + 1));
        stq_le_p(&s->regs_ro[RIO_REG_IOHPMCYCLES], 0);
        memset(&s->regs_ro[RIO_REG_IOHPMCTR_BASE], 0x00, s->hpm_cntrs * 8);
        memset(&s->regs_ro[RIO_REG_IOHPMEVT_BASE], 0x00, s->hpm_cntrs * 8);
    }
    stl_le_p(&s->regs_ro[RIO_REG_IVEC], 0);
    stq_le_p(&s->regs_rw[RIO_REG_DDTP], s->ddtp);
    /* If debug registers enabled. */
    if (s->cap & RIO_CAP_DBG) {
        stq_le_p(&s->regs_ro[RIO_REG_TR_REQ_IOVA], 0);
        stq_le_p(&s->regs_ro[RIO_REG_TR_REQ_CTRL], RIO_TRREQ_BUSY);
    }

    /* Memory region for untranslated MRIF/MSI writes */
    memory_region_init_io(&s->trap_mr, NULL, &riscv_iommu_trap_ops, s,
            "riscv-iommu-trap", ~0ULL);
    address_space_init(&s->trap_as, &s->trap_mr, "riscv-iommu-trap-as");

    /* Device translation context cache */
    s->ctx_cache = g_hash_table_new_full(__ctx_hash, __ctx_equal,
                                         g_free, NULL);
    s->iot_cache = g_hash_table_new_full(__iot_hash, __iot_equal,
                                         g_free, NULL);

    if (s->cap & RIO_CAP_HPM) {
        s->hpm_event_ctr_map = g_hash_table_new(g_direct_hash, g_direct_equal);
        pthread_rwlock_init(&s->ht_lock, NULL);
        s->hpm_timer =
            timer_new_ns(QEMU_CLOCK_VIRTUAL, riscv_iommu_hpm_timer_cb, s);
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
    if (s->cap & RIO_CAP_HPM) {
        timer_free(s->hpm_timer);
        pthread_rwlock_destroy(&s->ht_lock);
        g_hash_table_unref(s->hpm_event_ctr_map);
    }
    g_hash_table_unref(s->iot_cache);
    g_hash_table_unref(s->ctx_cache);
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

    int ea_off = pci_add_capability(dev, 0x14, 0, 16, &error_fatal);
    if (ea_off >= 0) {
        /* EAC.NumEntries := 1 */
        pci_set_long(dev->config + ea_off,
            pci_get_long(dev->config + ea_off) | (1 << 16));
        /* EAE.Enable := 0, EAE.EntrySize := 2, 32b address only */
        pci_set_long(dev->config + ea_off + 4, 4);
        /* Set EAE.Enable and base/max-offset writeable */
        pci_set_long(dev->wmask + ea_off + 4, 1u << 31);
        /* TODO: restrict writes to RoT role */
        pci_set_long(dev->wmask + ea_off + 8, ~0);
        pci_set_long(dev->wmask + ea_off + 12, ~0);
    }

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
    DEFINE_PROP_BOOL("intremap", RISCVIOMMUStatePci, iommu.enable_msi, TRUE),
    DEFINE_PROP_BOOL("ats", RISCVIOMMUStatePci, iommu.enable_ats, TRUE),
    DEFINE_PROP_BOOL("off", RISCVIOMMUStatePci, iommu.enable_off, TRUE),
    DEFINE_PROP_BOOL("s-stage", RISCVIOMMUStatePci, iommu.enable_s_stage, TRUE),
    DEFINE_PROP_BOOL("g-stage", RISCVIOMMUStatePci, iommu.enable_g_stage, TRUE),
    DEFINE_PROP_LINK("downstream-mr", RISCVIOMMUStatePci, iommu.down_mr,
            TYPE_MEMORY_REGION, MemoryRegion *),
    DEFINE_PROP_UINT8("hpm-counters", RISCVIOMMUStatePci, iommu.hpm_cntrs,
            RIO_IOHPMCTR_NUM_REGS),
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

    ctx = riscv_iommu_ctx(as->iommu, as->devid, iommu_idx, &ref);
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

static int riscv_iommu_memory_region_index(IOMMUMemoryRegion *iommu_mr,
        MemTxAttrs attrs)
{
    return attrs.unspecified ? 0 : (int)attrs.pasid;
}

static int riscv_iommu_memory_region_index_len(IOMMUMemoryRegion *iommu_mr)
{
    RISCVIOMMUSpace *as = container_of(iommu_mr, RISCVIOMMUSpace, iova_mr);
    return 1 << as->iommu->pasid_bits;
}

static void riscv_iommu_memory_region_init(ObjectClass *klass, void *data)
{
    IOMMUMemoryRegionClass *imrc = IOMMU_MEMORY_REGION_CLASS(klass);

    imrc->translate = riscv_iommu_memory_region_translate;
    imrc->notify_flag_changed = riscv_iommu_memory_region_notify;
    imrc->attrs_to_index = riscv_iommu_memory_region_index;
    imrc->num_indexes = riscv_iommu_memory_region_index_len;
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
