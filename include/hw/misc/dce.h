#ifndef DCE_H

#include "hw/registerfields.h"

REG32(DCE_CTRL, 0)
    FIELD(DCE_CTRL, ENABLE, 0, 1)
    FIELD(DCE_CTRL, RESET,  1, 2)

REG32(DCE_STATUS, 8)
    FIELD(DCE_STATUS, ENABLE, 0, 1)
    FIELD(DCE_STATUS, RESET,  1, 2)

REG32(DCE_DESCRIPTOR_RING_CTRL_BASE,  16)
REG32(DCE_DESCRIPTOR_RING_CTRL_LIMIT, 24)
REG32(DCE_DESCRIPTOR_RING_CTRL_HEAD,  32)
REG32(DCE_DESCRIPTOR_RING_CTRL_TAIL,  40)

REG32(DCE_INTERRUPT_CONFIG_DESCRIPTOR_COMPLETION, 48)
REG32(DCE_INTERRUPT_CONFIG_TIMEOUT,               56)
REG32(DCE_INTERRUPT_CONFIG_ERROR_CONDITION,       64)
REG32(DCE_INTERRUPT_STATUS,                       72)
REG32(DCE_INTERRUPT_MASK,                         80)

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

typedef struct DCEDescriptorRing {
    DCEDescriptor descriptors[9];
} QEMU_PACKED DCEDescriptorRing;

#endif // DCE_H