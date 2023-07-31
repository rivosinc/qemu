/*
 * RISC-V RAS (Reliability, Availability and Serviceability) block
 *
 * Copyright (c) 2023 Rivos Inc
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 or
 *  (at your option) any later version.
 */

#ifndef HW_MISC_RISCV_RAS_REGS_H
#define HW_MISC_RISCV_RAS_REGS_H

#define RECORD_NUM 1

typedef union RiscvRasControl {
    struct __attribute__((__packed__)) {
        uint16_t ele:1;
        uint16_t cece:1;
        uint16_t sinv:1;
        uint16_t rsvd0:1;
        uint16_t ces:2;
        uint16_t udes:2;
        uint16_t uues:2;
        uint16_t rsvd1:6;

        uint16_t rsvd2;

        uint16_t eid;

        uint16_t rsvd:8;
        uint16_t cust:8;
    };
    uint64_t u64;
} RiscvRasControl;

#define RAS_CTRL_MASK 0xFFFF000001FDull

_Static_assert(sizeof(RiscvRasControl) == sizeof(uint64_t));

typedef union RiscvRasStatus {
    struct __attribute__((__packed__)) {
        uint16_t v:1;
        uint16_t ce:1;
        uint16_t de:1;
        uint16_t ue:1;
        uint16_t pri:2;
        uint16_t mo:1;
        uint16_t c:1;
        uint16_t tt:3;
        uint16_t iv:1;
        uint16_t at:4;

        uint16_t siv:1;
        uint16_t tsv:1;
        uint16_t rsvd0:2;
        uint16_t scrub:1;
        uint16_t ceco:1;
        uint16_t rsvd1:2;
        uint16_t ec:8;

        uint16_t rsvd2;

        uint16_t cec:16;
   };
   uint64_t u64;
} RiscvRasStatus;

#define RAS_STS_MASK 0x7800003FFFFEull

_Static_assert(sizeof(RiscvRasStatus) == sizeof(uint64_t));

typedef struct __attribute__((__packed__)) RiscvRasErrorRecord {
    RiscvRasControl control_i;
    RiscvRasStatus status_i;
    uint64_t addr_i;
    uint64_t info_i;
    uint64_t suppl_info_i;
    uint64_t timestamp_i;
    uint64_t reserved;
    uint64_t custom;
} RiscvRasErrorRecord;

typedef union RiscvRaSComponentId {
    struct __attribute__((__packed__)) {
        uint16_t inst_id;
        uint16_t n_err_recs;
        uint64_t reserved0:24;
        uint8_t version:8;
    };
    uint64_t u64;
} RiscvRaSComponentId;

_Static_assert(sizeof(RiscvRaSComponentId) == sizeof(uint64_t));

typedef union RiscvRaSVendorId {
    struct __attribute__((__packed__)) {
        uint32_t vendor_id;
        uint16_t imp_id;
        uint16_t reserved;
    };
    uint64_t u64;
} RiscvRaSVendorId;

_Static_assert(sizeof(RiscvRaSVendorId) == sizeof(uint64_t));

typedef struct __attribute__((__packed__)) RiscvRasErrorPage {
    RiscvRaSVendorId vendor_n_imp_id;
    RiscvRaSComponentId component_id;
    uint64_t valid_summary;
    uint64_t reserved[2];
    uint64_t custom[3];
    RiscvRasErrorRecord records[RECORD_NUM];
} RiscvRasComponentRegisters;

#endif
