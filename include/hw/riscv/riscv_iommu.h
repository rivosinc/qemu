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

#ifndef HW_RISCV_IOMMU_H
#define HW_RISCV_IOMMU_H

#include "qemu/osdep.h"
#include "qom/object.h"

/*
 * IOMMU Interface Specification - based on RISC-V Ziommu Document.
 * Published at https://github.com/riscv-non-isa/riscv-iommu rev Aug 1st, 2022
 */

/* Register Layout - Chapter 5. Memory-mapped register interface */
#define RIO_REG_CAP             0x0000
#define RIO_REG_FCTRL           0x0008
#define RIO_REG_DDTP            0x0010
#define RIO_REG_CQB             0x0018
#define RIO_REG_CQH             0x0020
#define RIO_REG_CQT             0x0024
#define RIO_REG_FQB             0x0028
#define RIO_REG_FQH             0x0030
#define RIO_REG_FQT             0x0034
#define RIO_REG_PQB             0x0038
#define RIO_REG_PQH             0x0040
#define RIO_REG_PQT             0x0044
#define RIO_REG_CQCSR           0x0048
#define RIO_REG_FQCSR           0x004C
#define RIO_REG_PQCSR           0x0050
#define RIO_REG_IPSR            0x0054
#define RIO_REG_IOCNTOVF        0x0058
#define RIO_REG_IOCNTINH        0x005C
#define RIO_REG_IOHPMCYCLES     0x0060
#define RIO_REG_IOHPMCTR_BASE   0x0068
#define RIO_REG_IOHPMCTR_END    0x0158
#define RIO_REG_IOHPMEVT_BASE   0x0160
#define RIO_REG_IOHPMEVT_END    0x0250
#define RIO_REG_TR_REQ_IOVA     0x0258
#define RIO_REG_TR_REQ_CTRL     0x0260
#define RIO_REG_TR_RESPONSE     0x0268
#define RIO_REG_IVEC            0x02F8
#define RIO_REG_MSI_CONFIG      0x0300

#define RIO_REG_SIZE            0x1000

/* Capabilities supported by the IOMMU, RIO_REG_CAP */
#define RIO_CAP_S_SV32         (1ULL << 8)
#define RIO_CAP_S_SV39         (1ULL << 9)
#define RIO_CAP_S_SV48         (1ULL << 10)
#define RIO_CAP_S_SV57         (1ULL << 11)
#define RIO_CAP_SVNAPOT        (1ULL << 14)
#define RIO_CAP_SVPBMT         (1ULL << 15)
#define RIO_CAP_G_SV32         (1ULL << 16)
#define RIO_CAP_G_SV39         (1ULL << 17)
#define RIO_CAP_G_SV48         (1ULL << 18)
#define RIO_CAP_G_SV57         (1ULL << 19)
#define RIO_CAP_MSI_FLAT       (1ULL << 22)
#define RIO_CAP_MSI_MRIF       (1ULL << 23)
#define RIO_CAP_AMO            (1ULL << 24)
#define RIO_CAP_ATS            (1ULL << 25)
#define RIO_CAP_T2GPA          (1ULL << 26)
#define RIO_CAP_END            (1ULL << 27)
#define RIO_CAP_IGS_WIS        (1ULL << 28)
#define RIO_CAP_IGS_BOTH       (1ULL << 29)
#define RIO_CAP_HPM            (1ULL << 30)
#define RIO_CAP_DBG            (1ULL << 31)

#define RIO_CAP_REV_MASK        0x00000000000000FFULL
#define RIO_CAP_PAS_MASK        0x0000003F00000000ULL

/* Features control register, RIO_REG_FCTRL */
#define RIO_FCTRL_END           (1ULL << 0)
#define RIO_FCTRL_WIS           (1ULL << 1)

/* Device directory table pointer */
#define RIO_DDTP_MASK_PPN       0x003FFFFFFFFFFC00ULL
#define RIO_DDTP_MASK_MODE      0x000000000000000FULL
#define RIO_DDTP_BUSY           0x0000000000000010ULL

#define RIO_DDTE_VALID         (1ULL << 0)
#define RIO_DDTE_MASK_PPN       0x003FFFFFFFFFFC00ULL

/* Device directory mode values, within RIO_DDTP_MASK_MODE */
#define RIO_DDTP_MODE_OFF       0
#define RIO_DDTP_MODE_BARE      1
#define RIO_DDTP_MODE_1LVL      2
#define RIO_DDTP_MODE_2LVL      3
#define RIO_DDTP_MODE_3LVL      4
#define RIO_DDTP_MODE_MAX       RIO_DDTP_MODE_3LVL

/* Command queue base register */
#define RIO_CQ_MASK_LOG2SZ      0x000000000000001FULL
#define RIO_CQ_MASK_PPN         0x003FFFFFFFFFFC00ULL

/* Command queue control and status register */
#define RIO_CQ_EN              (1 << 0)
#define RIO_CQ_IE              (1 << 1)
#define RIO_CQ_FAULT           (1 << 8)
#define RIO_CQ_TIMEOUT         (1 << 9)
#define RIO_CQ_ERROR           (1 << 10)
#define RIO_CQ_FENCE_W_IP      (1 << 11)
#define RIO_CQ_ACTIVE          (1 << 16)
#define RIO_CQ_BUSY            (1 << 17)

/* Fault queue base register */
#define RIO_FQ_MASK_LOG2SZ      0x000000000000001FULL
#define RIO_FQ_MASK_PPN         0x003FFFFFFFFFFC00ULL

/* Fault queue control and status register */
#define RIO_FQ_EN              (1 << 0)
#define RIO_FQ_IE              (1 << 1)
#define RIO_FQ_FAULT           (1 << 8)
#define RIO_FQ_FULL            (1 << 9)
#define RIO_FQ_ACTIVE          (1 << 16)
#define RIO_FQ_BUSY            (1 << 17)

/* Page request queue base register */
#define RIO_PQ_MASK_LOG2SZ      0x000000000000001FULL
#define RIO_PQ_MASK_PPN         0x003FFFFFFFFFFC00ULL

/* Page request queue control and status register */
#define RIO_PQ_EN              (1 << 0)
#define RIO_PQ_IE              (1 << 1)
#define RIO_PQ_FAULT           (1 << 8)
#define RIO_PQ_FULL            (1 << 9)
#define RIO_PQ_ACTIVE          (1 << 16)
#define RIO_PQ_BUSY            (1 << 17)

/* Interrupt Sources, used for IPSR and IVEC indexing. */
#define RIO_INT_CQ              0
#define RIO_INT_FQ              1
#define RIO_INT_PM              2
#define RIO_INT_PQ              3
#define RIO_INT_COUNT           4

#define RIO_IPSR_CQIP          (1 << RIO_INT_CQ)
#define RIO_IPSR_FQIP          (1 << RIO_INT_FQ)
#define RIO_IPSR_PMIP          (1 << RIO_INT_PM)
#define RIO_IPSR_PQIP          (1 << RIO_INT_PQ)

/* HPM event counter register. */
#define RIO_IOHPMCTR_NUM_REGS        31
#define RIO_IOHPMEVT_NUM_REGS        31

#define RIO_IOCNTOVF_CY             (1ULL << 0)

#define RIO_IOCNTINH_CY             (1ULL << 0)

#define RIO_IOHPMCYCLES_MASK_CNTR    0x7FFFFFFFFFFFFFFFULL
#define RIO_IOHPMCYCLES_OF          (1ULL << 63)

#define RIO_IOHPMEVT_MASK_EID        0x0000000000007FFFULL
#define RIO_IOHPMEVT_MASK_PID_PSCID  0x0000000FFFFF0000ULL
#define RIO_IOHPMEVT_MASK_DID_GSCID  0x0FFFFFF000000000ULL

#define RIO_IOHPMEVT_DMASK          (1ULL << 15)
#define RIO_IOHPMEVT_PV_PSCV        (1ULL << 60)
#define RIO_IOHPMEVT_DV_GSCV        (1ULL << 61)
#define RIO_IOHPMEVT_IDT            (1ULL << 62)
#define RIO_IOHPMEVT_OF             (1ULL << 63)

/* Interrupt vector mapping */
#define RIO_IVEC_CQIV          (0x0F << 0)
#define RIO_IVEC_FQIV          (0x0F << 4)
#define RIO_IVEC_PMIV          (0x0F << 8)
#define RIO_IVEC_PQIV          (0x0F << 12)

/* Translation request interface */
#define RIO_TRREQ_BUSY         (1ULL << 0)
#define RIO_TRREQ_PRIV         (1ULL << 1)
#define RIO_TRREQ_EXEC         (1ULL << 2)
#define RIO_TRREQ_RO           (1ULL << 3)
#define RIO_TRREQ_PV           (1ULL << 32)

#define RIO_TRREQ_MASK_DID      0xFFFFFF0000000000ULL
#define RIO_TRREQ_MASK_PID      0x00000000FFFFF000ULL

#define RIO_TRRSP_FAULT         (1ULL << 0)
#define RIO_TRRSP_S             (1ULL << 9)
#define RIO_TRRSP_MASK_PBMT     0x0000000000000180ULL
#define RIO_TRRSP_MASK_PPN      0x003FFFFFFFFFFC00ULL

/* Device Context */
typedef struct RISCVIOMMUDeviceContext {
    uint64_t  tc;          /* Translation Control */
    uint64_t  gatp;        /* G-Stage address translation and protection */
    uint64_t  ta;          /* Translation attributes */
    uint64_t  fsc;         /* S-Stage address translation and protection */
    uint64_t  msiptp;      /* MSI Page Table Pointer (extended context) */
    uint64_t  msi_addr_mask;
    uint64_t  msi_addr_pattern;
    uint64_t  _reserved;
} RISCVIOMMUDeviceContext;

#define RIO_DCTC_VALID            (1ULL << 0)
#define RIO_DCTC_EN_ATS           (1ULL << 1)
#define RIO_DCTC_EN_PRI           (1ULL << 2)
#define RIO_DCTC_T2GPA            (1ULL << 3)
#define RIO_DCTC_DTF              (1ULL << 4)
#define RIO_DCTC_PDTV             (1ULL << 5)
#define RIO_DCTC_PRPR             (1ULL << 6)
#define RIO_DCTC_GADE             (1ULL << 7)
#define RIO_DCTC_SADE             (1ULL << 8)

/* Shared MODE:ASID:PPN masks for GATP, SATP */
#define RIO_ATP_MASK_PPN           0x00000FFFFFFFFFFFULL
#define RIO_ATP_MASK_GSCID         0x0FFFF00000000000ULL
#define RIO_ATP_MASK_MODE          0xF000000000000000ULL

/* Shared MODE:ASID:PPN masks for GATP, SATP */
#define RIO_ATP_MODE_BARE          0
#define RIO_ATP_MODE_SV32          1
#define RIO_ATP_MODE_SV39          8
#define RIO_ATP_MODE_SV48          9
#define RIO_ATP_MODE_SV57          10

/* FSC mode field when TC.RIO_TC_PDTV is set */
#define RIO_PDTP_MODE_BARE         0
#define RIO_PDTP_MODE_PD20         1
#define RIO_PDTP_MODE_PD17         2
#define RIO_PDTP_MODE_PD8          3

#define RIO_PDTE_VALID            (1ULL << 0)
#define RIO_PDTE_MASK_PPN          0x003FFFFFFFFFFC00ULL

#define RIO_DCMSI_MASK_PPN         0x00000FFFFFFFFFFFULL
#define RIO_DCMSI_MASK_MODE        0xF000000000000000ULL

#define RIO_DCMSI_MODE_OFF         0
#define RIO_DCMSI_MODE_FLAT        1

#define RIO_MSIPTE_V              (1ULL << 0)
#define RIO_MSIPTE_W              (1ULL << 2)
#define RIO_MSIPTE_C              (1ULL << 63)

#define RIO_MSIPTE_MASK_PPN        0x003FFFFFFFFFFC00ULL
#define RIO_MRIF_ADDR_MASK_PPN     0x003FFFFFFFFFFF80ULL

#define RIO_MRIF_NPPN_MASK_PPN     0x003FFFFFFFFFFC00ULL
#define RIO_MRIF_NPPN_MASK_N90     0x00000000000003FFULL
#define RIO_MRIF_NPPN_MASK_N10     0x1000000000000000ULL

typedef struct RISCVIOMMUProcessContext {
    uint64_t ta;
    uint64_t fsc;
} RISCVIOMMUProcessContext;

#define RIO_PCTA_V                (1 << 0)
#define RIO_PCTA_ENS              (1 << 1)
#define RIO_PCTA_SUM              (1 << 2)
#define RIO_PCTA_MASK_PSCID        0x00000000FFFFF000ULL

/* I/O Management Unit Command format */
typedef struct RISCVIOMMUCommand {
    uint64_t request;
    uint64_t address;
} RISCVIOMMUCommand;

/* RISCVIOMMUCommand.request opcode and function mask */
#define RIO_CMD_MASK_OP            0x000000000000007FULL
#define RIO_CMD_MASK_FUNC          0x0000000000000380ULL

#define RIO_CMD_IOTINVAL           0x001
#define RIO_CMD_IOFENCE            0x002
#define RIO_CMD_IODIR              0x003
#define RIO_CMD_ATS                0x004

/* opcode == IOTINVAL */

#define RIO_IOTINVAL_FLAGS         0x00003F80

#define RIO_IOTINVAL_GSTAGE        0x00000080
#define RIO_IOTINVAL_MSI           0x00000100
#define RIO_IOTINVAL_PSCID_VALID   0x00000400
#define RIO_IOTINVAL_ADDR_VALID    0x00000800
#define RIO_IOTINVAL_GSCID_VALID   0x00001000
#define RIO_IOTINVAL_ADDR_NAPOT    0x00002000

#define RIO_IOTINVAL_MASK_PSCID    0x0000000FFFFF0000ULL
#define RIO_IOTINVAL_MASK_GSCID    0x00FFFF0000000000ULL

/* opcode == IOFENCE.* */

#define RIO_IOFENCE_PR             0x00000400
#define RIO_IOFENCE_PW             0x00000800
#define RIO_IOFENCE_AV             0x00001000

#define RIO_IOFENCE_MASK_DATA      0xFFFFFFFF00000000ULL

/* opcode == IODIR.* */
#define RIO_IODIR_PID_VALID        0x00000080
#define RIO_IODIR_DID_VALID        0x00000400

#define RIO_IODIR_MASK_PID         0x0000000FFFFF0000ULL
#define RIO_IODIR_MASK_DID         0xFFFFFF0000000000ULL

/* opcode == ATS */
#define RIO_ATSOP_PRGR             0x00000080
#define RIO_ATSOP_DSV              0x00000400
#define RIO_ATSOP_PV               0x00000800

#define RIO_ATSOP_MASK_PID         0x0000000FFFFF0000ULL
#define RIO_ATSOP_MASK_DSEG        0x0000FF0000000000ULL
#define RIO_ATSOP_MASK_RID         0xFFFF000000000000ULL

/* Fault Queue element */
typedef struct RISCVIOMMUEvent {
    uint64_t reason;
    uint64_t _rsrvd;
    uint64_t iova;
    uint64_t phys;
} RISCVIOMMUEvent;

/* Event reason */
#define RIO_EVENT_MASK_DID         0x0000000000FFFFFFULL
#define RIO_EVENT_MASK_PID         0x00000FFFFF000000ULL
#define RIO_EVENT_PV               0x0000100000000000ULL
#define RIO_EVENT_PRIV             0x0000200000000000ULL
#define RIO_EVENT_MASK_TTYPE       0x000FC00000000000ULL
#define RIO_EVENT_MASK_CAUSE       0xFFF0000000000000ULL

/* RISC-V IOMMU Fault Transaction Type / Exception Codes */

#define RIO_TTYP_NONE               0 /* Fault not caused by an inbound trx */
#define RIO_TTYP_URX                1 /* Untranslated read for execute trx */
#define RIO_TTYP_URD                2 /* Untranslated read transaction */
#define RIO_TTYP_UWR                3 /* Untranslated write/AMO transaction */
#define RIO_TTYP_TRX                4 /* Translated read for execute trx */
#define RIO_TTYP_TRD                5 /* Translated read transaction */
#define RIO_TTYP_TWR                6 /* Translated write/AMO transaction */
#define RIO_TTYP_ATS                7 /* PCIe ATS Translation Request */
#define RIO_TTYP_MRQ                8 /* Message Request */

#define RIO_CAUSE_EX_FAULT          1 /* Instruction access fault */
#define RIO_CAUSE_RD_FAULT          5 /* Read access fault */
#define RIO_CAUSE_WR_FAULT          7 /* Write/AMO access fault */
#define RIO_CAUSE_EX_FAULT_S       12 /* Instruction page fault */
#define RIO_CAUSE_RD_FAULT_S       13 /* Read page fault */
#define RIO_CAUSE_WR_FAULT_S       15 /* Write/AMO page fault */
#define RIO_CAUSE_EX_FAULT_G       20 /* Instruction guest page fault */
#define RIO_CAUSE_RD_FAULT_G       21 /* Read guest-page fault */
#define RIO_CAUSE_WR_FAULT_G       23 /* Write/AMO guest-page fault */
#define RIO_CAUSE_DMA_DISABLED    256 /* Inbound transactions disallowed */
#define RIO_CAUSE_DDT_FAULT       257 /* DDT entry load access fault */
#define RIO_CAUSE_DDT_INVALID     258 /* DDT entry not valid */
#define RIO_CAUSE_DDT_UNSUPPORTED 259 /* DDT entry misconfigured */
#define RIO_CAUSE_REQ_INVALID     260 /* Transaction type disallowed */
#define RIO_CAUSE_MSI_PTE_FAULT   261 /* MSI PTE load access fault */
#define RIO_CAUSE_MSI_INVALID     262 /* MSI PTE not valid */
#define RIO_CAUSE_MSI_UNSUPPORTED 263 /* MSI PTE entry misconfigured */
#define RIO_CAUSE_MRIF_FAULT      264 /* MRIF access fault */
#define RIO_CAUSE_PDT_FAULT       265 /* PDT load access fault */
#define RIO_CAUSE_PDT_INVALID     266 /* PDT not valid */
#define RIO_CAUSE_PDT_UNSUPPORTED 267 /* PDT entry misconfigured */
#define RIO_CAUSE_DDT_CORRUPTED   268 /* DDT entry corrupted */
#define RIO_CAUSE_PDT_CORRUPTED   269 /* PDT entry corrupted */
#define RIO_CAUSE_MSI_CORRUPTED   270 /* MSI entry corrupted */
#define RIO_CAUSE_MRIF_CORRUPTED  271 /* DDT entry corrupted */
#define RIO_CAUSE_ERROR           272 /* Internal data error */
#define RIO_CAUSE_MSI_FAULT       273 /* MSI write access fault */

/*
 * HPM Event IDs. See IOMMU Specification, Chapter 5.23.
 * Performance-monitoring event selector.
 */
enum RISCVIOMMUEventID {
    RIO_HPMEVENT_INVALID,    /* Invalid event, do not count */
    RIO_HPMEVENT_URQ,        /* Untranslated requests */
    RIO_HPMEVENT_TRQ,        /* Translated requests */
    RIO_HPMEVENT_ATS_RQ,     /* ATS translation requests */
    RIO_HPMEVENT_TLB_MISS,   /* TLB misses */
    RIO_HPMEVENT_DD_WALK,    /* Device directory walks */
    RIO_HPMEVENT_PD_WALK,    /* Process directory walks */
    RIO_HPMEVENT_S_VS_WALKS, /* S/VS-Stage page table walks */
    RIO_HPMEVENT_G_WALKS,    /* G-Stage page table walks */
    RIO_HPMEVENT_MAX,        /* Value to denote maximum Event IDs */
};

/* QEMU RISC-V IOMMU Device Emulation Objects */

#define TYPE_RISCV_IOMMU_MEMORY_REGION "x-riscv-iommu-mr"
typedef struct RISCVIOMMUSpace RISCVIOMMUSpace;

#define TYPE_RISCV_IOMMU_PCI "x-riscv-iommu-pci"
OBJECT_DECLARE_SIMPLE_TYPE(RISCVIOMMUStatePci, RISCV_IOMMU_PCI)
typedef struct RISCVIOMMUStatePci RISCVIOMMUStatePci;

#define TYPE_RISCV_IOMMU_SYS "x-riscv-iommu-device"
OBJECT_DECLARE_SIMPLE_TYPE(RISCVIOMMUStateSys, RISCV_IOMMU_SYS)
typedef struct RISCVIOMMUStateSys RISCVIOMMUStateSys;

#endif

