#ifndef DCE_H

#include "hw/registerfields.h"
#include "qemu/osdep.h"
#include "qom/object.h"

REG32(DCE_CTRL, 0)
    FIELD(DCE_CTRL, ENABLE, 0, 1)
    FIELD(DCE_CTRL, RESET,  1, 2)

REG32(DCE_STATUS, 8)
    FIELD(DCE_STATUS, ENABLE, 0, 1)
    FIELD(DCE_STATUS, RESET,  1, 2)

REG64(DCE_COMPLETION, 0)
    FIELD(DCE_COMPLETION, DATA, 0, 56)
    FIELD(DCE_COMPLETION, SPEC, 56, 4)
    FIELD(DCE_COMPLETION, STATUS, 60, 3)
    FIELD(DCE_COMPLETION, VALID, 63, 1)

REG32(DCE_INTERRUPT_CONFIG_DESCRIPTOR_COMPLETION, 48)
REG32(DCE_INTERRUPT_CONFIG_TIMEOUT,               56)
REG32(DCE_INTERRUPT_CONFIG_ERROR_CONDITION,       64)
REG32(DCE_INTERRUPT_STATUS,                       72)
REG32(DCE_INTERRUPT_MASK,                         80)

enum {
    STATUS_PASS = 0,
    STATUS_FAIL
};

typedef enum DCEInterruptSource {
    DCE_INTERRUPT_DESCRIPTOR_COMPLETION = 0,
    DCE_INTERRUPT_TIMEOUT               = 1,
    DCE_INTERRUPT_ERROR_CONDITION       = 2,
    DCE_INTERRUPT_MAX                   = 3
} DCEInterruptSource;

typedef struct InterruptSourceInfo {
    uint32_t vector_index;
    bool enable;
} InterruptSourceInfo;



// REG32(DCE_INTERRUPT_STATUS    , 32)
// REG32(DCE_INTERRUPT_MASK      , 40)

// more MMIO registers TBD

// #define DCE_DESCRIPTOR_RING_START 0x100
// #define DCE_DESCRIPTOR_RING_OFFSET_BASE  0
// #define DCE_DESCRIPTOR_RING_OFFSET_LIMIT 8
// #define DCE_DESCRIPTOR_RING_OFFSET_HEAD  16
// #define DCE_DESCRIPTOR_RING_OFFSET_TAIL  24

static const int RING_HEADER_HEAD_OFFSET = 0;
static const int RING_HEADER_TAIL_OFFSET = 64;

typedef struct DCEDescriptor {
    uint8_t  opcode;
    uint8_t  ctrl;
    uint16_t operand0;
    uint32_t pasid;
    uint64_t source;
    uint64_t dest;
    uint64_t completion;
    uint64_t operand1;
    uint64_t operand2;
    uint64_t operand3;
    uint64_t operand4;
} QEMU_PACKED DCEDescriptor;

#define SRC_IS_LIST                 (1 << 1)
#define SRC2_IS_LIST                (1 << 2)
#define DEST_IS_LIST                (1 << 3)
#define PASID_VALID                 (1 << 4)

/* OPCODE VALUES */
#define DCE_OPCODE_CLFLUSH            0
#define DCE_OPCODE_MEMCPY             1
#define DCE_OPCODE_MEMSET             2
#define DCE_OPCODE_MEMCMP             3
#define DCE_OPCODE_COMPRESS           4
#define DCE_OPCODE_DECOMPRESS         5
#define DCE_OPCODE_LOAD_KEY           6
#define DCE_OPCODE_CLEAR_KEY          7
#define DCE_OPCODE_ENCRYPT            8
#define DCE_OPCODE_DECRYPT            9
#define DCE_OPCODE_DECRYPT_DECOMPRESS 10
#define DCE_OPCODE_COMPRESS_ENCRYPT   11
/* CRC Opcodes */
#define DCE_OPCODE_CRC_GEN            12
#define DCE_OPCODE_MEMCPY_CRC_GEN     13
/* PI Opcodes */
#define DCE_OPCODE_DIF_CHK            14
#define DCE_OPCODE_DIF_GEN            15
#define DCE_OPCODE_DIF_UPD            16
#define DCE_OPCODE_DIF_STRP           17
#define DCE_OPCODE_DIX_CHK            18
#define DCE_OPCODE_DIX_GEN            19

#ifdef CONFIG_DCE_CRYPTO
/* OPERAND 0 for Security/Efficiency */
/* sec_algo field enum*/
typedef enum {
    AES=0,
    SM4=1,
} SecAlgo;
static SecAlgo op0_get_sec_algo(uint16_t op0){
    return extract16(op0, 0, 1);
}
/* sec_func field enum*/
typedef enum {
    XTS=0,
    GCM=1,
} SecMode;
static SecMode op0_get_sec_mode(uint16_t op0){
    return extract16(op0, 4, 1);
}
#endif

/* comp_format field enum */
typedef enum {
    RLE = 0,
    Snappy,
    LZ4,
    GZIP,
    ZSTD
} CompFormat;
static CompFormat op0_get_comp_format(uint16_t op0){
    return extract16(op0, 1, 3);
}


enum {
    TO_LOCAL,
    FROM_LOCAL
};

enum {
    COMPRESS,
    DECOMPRESS
};

enum {
    ENCRYPT,
    DECRYPT
};

enum {
    IDLE,
    READY_TO_RUN
};

enum {
    DCE_EXEC_WQMCC,
    DCE_EXEC_NOTIFY,
    DCE_EXEC_READY_TO_RUN,
    DCE_EXEC_RESET_ARB_WEIGHT,
    DCE_EXEC_GLOBAL_CONFIG,
    DCE_EXEC_LAST
};

typedef struct __attribute__((packed)) WQITE {
    uint64_t DSCBA;
    uint8_t  DSCSZ;
    uint64_t DSCPTA;
    uint32_t TRANSCTL;
    uint64_t WQ_CTX_SAVE_BA;
    // TBA: key slot management
} __attribute__((packed)) WQITE;

// WQCR
REG32(DCE_WQCR,     96)
    FIELD(DCE_WQCR, NOTIFY, 0, 1)
    FIELD(DCE_WQCR, ABORT, 8, 1)
    FIELD(DCE_WQCR, STATUS, 16, 1)

#define WQMCC                       0
#define GLOB_CONF                   127

REG64(DCE_TRANSCTL, 0)
    FIELD(DCE_TRANSCTL, TRANSCTL_SUPV, 31, 1)
    FIELD(DCE_TRANSCTL, TRANSCTL_PASID_V, 30, 1)
    FIELD(DCE_TRANSCTL, TRANSCTL_PASID, 0, 20)

/* WQMCC Page */
#define DCE_REG_WQITBA                  0x0
#define DCE_REG_WQRUNSTS                0x10
#define DCE_REG_WQENABLE                0x18
#define DCE_REG_WQIRQSTS                0x20

/* WQCR Page */
#define DCE_REG_WQCR                    0x0

/* Global Config Page */
#define DCE_REG_FUNC_SAVE               0x0  /* 0x0 - 0x40 */
#define DCE_REG_FUNC_SAVE_TRANS_CTL     0x40
#define DCE_REG_ARB_WGT                 0x48 /* 0x48 - 0x50 */
#define DCE_REG_KEY_SLOT_OWNERSHIP      0x50 /* 0x50 - 0x60 */
#define DCE_REG_FUNC_WQ_PROCESSING_CTL  0x60
#define DCE_REG_FUNC_WQ_RUN_STS         0x68 /* 0x68 - 0x78 */

typedef enum {
    _16GB = 0,
    _32GB = 1,
    _64GB = 2,
    PIF_RESERVED = 3,
} PIF_encoding;

typedef enum {
    TYPE_1,
    TYPE_2,
    TYPE_3,
    TYPE_4,
} Protection_type;

typedef enum {
    NO_PI_ERROR,
    INVALID_PI_DESCRIPTOR,
    INVALID_PI,
    GUARD_CHECK_FAILED,
    APPLICATION_TAG_CHECK_FAILED,
    STORAGE_TAG_CHECK_FAILED,
    REFERENCE_TAG_CHECK_FAILED,
} PI_error_codes;

/* PI fields */
REG16(FMT_INFO, 0)
    FIELD(FMT_INFO, _LBAS, 14, 2)
    FIELD(FMT_INFO, _PIF, 12, 2)
    FIELD(FMT_INFO, _ATS, 7, 5)
    FIELD(FMT_INFO, _STS, 0, 7)

/* CRC fields */
REG16(CRC_CTRL, 0)
    FIELD(CRC_CTRL, PAD_BIT, 5, 1)
    FIELD(CRC_CTRL, REFLECT_OUT, 4, 1)
    FIELD(CRC_CTRL, REFLECT_IN, 3, 1)
    FIELD(CRC_CTRL, WIDTH, 0, 3)

REG16(JOB_CTRL, 0)
    FIELD(JOB_CTRL, NUM_BYTES, 0, 48)


#define TYPE_RISCV_DCE_MEMORY_REGION "x-riscv-dce-mr"
typedef struct RISCVDCESpace RISCVDCESpace;

#define TYPE_RISCV_DCE_PCI "x-riscv-dce-pci"
OBJECT_DECLARE_SIMPLE_TYPE(RISCVDCEStatePci, RISCV_DCE_PCI)
typedef struct RISCVDCEStatePci RISCVDCEStatePci;

#define TYPE_RISCV_DCE_SYS "x-riscv-dce-device"
OBJECT_DECLARE_SIMPLE_TYPE(RISCVDCEStateSys, RISCV_DCE_SYS)
typedef struct RISCVDCEStateSys RISCVDCEStateSys;

#endif // DCE_H
