#include "qemu/osdep.h"
#include "qemu/log.h"
#include "hw/qdev-properties.h"
#include "migration/vmstate.h"
#include "qom/object.h"
#include "hw/irq.h"
#include "hw/pci/pci.h"
#include "hw/pci/msi.h"
#include "hw/hw.h"
#include "hw/misc/dce.h"
#include "qemu/atomic.h"
#include <signal.h>
#include <stdint.h>
// #include "hw/riscv/riscv_hart.h" FIXME
#define DCE_PAGE_SIZE  (1 << 12)

#ifdef CONFIG_DCE_COMPRESSION
#include "lz4.h"
#include "snappy-c.h"
#include "zlib.h"
#include "zstd.h"
#endif // CONFIG_DCE_COMPRESSION

#ifdef CONFIG_DCE_CRYPTO
#include "dce-crypto.h"
#endif // CONFIG_DCE_CRYPTO

#include "qapi/visitor.h"

#define reg_addr(reg) (A_ ## reg)
#define DCE_AES_KEYLEN    32
#define DCE_MAC_LEN       16
#define NUM_WQ            64

#define DCE_CAP_SRIOV_OFFSET 0x160
#define DCE_TOTAL_VFS 7
#define DCE_VF_OFFSET 0x80
#define DCE_VF_STRIDE 1

#define DCE_DEFAULT_ARB_WEIGHT 0x0101010101010101LLU

#define NUM_KEY_SLOTS 8

typedef struct DCEState
{
    PCIDevice dev;
    MemoryRegion mmio;

    uint8_t regs_rw[128][DCE_PAGE_SIZE];  /* 512 Kib MMIO register state */
    uint8_t regs_ro[128][DCE_PAGE_SIZE];  /* 512 Kib MMIO register state */

    bool enable;
    uint64_t dma_mask;

    /* Storage for NUM_KEYS 32B keys */
    unsigned char keys[NUM_KEY_SLOTS][32];

    QemuThread core_proc; /* Background processing thread */
    QemuCond core_cond;   /* Background processing wakeup signal */
    QemuMutex core_lock;  /* Global IOMMU lock, used for cache/regs updates */
    unsigned core_exec;   /* Processing thread execution actions */

    /* PASID attrs */
    bool enable_pasid;

    /* only used by VFs */
    struct DCEState * pfstate;
    bool isVF;
    int vfnum;

    /* only used by PF */
    struct DCEState * all_states[DCE_TOTAL_VFS + 1]; /* first DCE_TOTAL_VFS are VF entries, last one is PF */

    /* global config */
    uint64_t arb_weight;
    uint32_t arb_weight_sum;
} DCEState;

static bool dce_msi_enabled(DCEState *state)
{
    return msi_enabled(&state->dev);
}

static void dce_raise_interrupt(DCEState *state, int WQ_id,
                DCEInterruptSource val)
{
    /* TODO: support other interrupts */
    /* TODO: lock */
    printf("Issuing interrupt for WQ %d, %d!\n", WQ_id, val);
    uint64_t irq_status = ldq_le_p(&state->regs_rw[WQMCC][DCE_REG_WQIRQSTS]);
    irq_status |= BIT(WQ_id);
    stq_le_p(&state->regs_rw[WQMCC][DCE_REG_WQIRQSTS], irq_status);
    // irq_status |= BIT(val);
    if (irq_status) {
        if (dce_msi_enabled(state)) {
            msi_notify(&state->dev, 0);
        }
    }
}

// static void dce_lower_interrupt(DCEState *state, DCEInterruptSource val)
// {
//     state->irq_status &= ~val;
// }

// static void reset(DCEState *state)
// {
//     // TODO: fill this out later when it's clear what happens here
// }

static bool aligned(hwaddr addr, unsigned size)
{
    return addr % size == 0;
}

static inline bool interrupt_on_completion(DCEState *state,
                                           struct DCEDescriptor *descriptor)
{
    // printf("ctrl is 0x%x\n", descriptor->ctrl);
    // printf("MSI enabled? %d\n", dce_msi_enabled(state));
    return (descriptor->ctrl & 1);
}

static uint64_t populate_completion(uint8_t status, uint8_t spec, uint64_t data)
{
    uint64_t completion = 0;
    completion = FIELD_DP64(completion, DCE_COMPLETION, DATA, data);
    completion = FIELD_DP64(completion, DCE_COMPLETION, SPEC, spec);
    completion = FIELD_DP64(completion, DCE_COMPLETION, STATUS, status);
    completion = FIELD_DP64(completion, DCE_COMPLETION, VALID, 1);
    return completion;
}

static void complete_workload(DCEState *state, struct DCEDescriptor *descriptor,
                              int err, uint8_t spec, uint64_t data, MemTxAttrs * attrs)
{
    int status = STATUS_PASS;
    uint64_t completion = 0;

    if (err) {
        printf("ERROR: operation has failed, %d!\n", err);
        status = STATUS_FAIL;
    }
    completion = populate_completion(status, spec, data);

    pci_dma_rw(&state->dev, descriptor->completion,
        &completion, 8, DMA_DIRECTION_FROM_DEVICE, *attrs);
}

/* Data processing functions */
static void get_next_ptr_and_size(PCIDevice * dev, uint64_t * entry,
                                  uint64_t * curr_ptr, uint64_t * curr_size,
                                  bool is_list, size_t size, MemTxAttrs * attrs)
{
    int err = 0;
    uint64_t next_level_entry = *entry;
    if (is_list) {
        do {
            *entry = next_level_entry;
            err |= pci_dma_rw(dev, *entry, curr_ptr, 8,
                        DMA_DIRECTION_TO_DEVICE, *attrs);
            err |= pci_dma_rw(dev, (*entry) + 8, curr_size, 8,
                        DMA_DIRECTION_TO_DEVICE, *attrs);
            next_level_entry = *curr_ptr;
        } while((size & (1ULL << 63)) != 0);
    }
    else {
        *curr_ptr = *entry;
        *curr_size = size;
    }

    if (err) {
        printf("ERROR in %s!\n", __func__);
    } else {
        // printf("Read buffer: 0x%lx\n",  *curr_ptr);
        // printf("Read size: 0x%lx\n", *curr_size);
    }
}

static int local_buffer_transfer(DCEState *state,
                                uint8_t * local, hwaddr src, size_t size,
                                bool is_list, int dir, MemTxAttrs * attrs) {
    /* Initialize attrs for PASID */

    int err = 0, bytes_finished = 0;
    uint64_t curr_ptr;
    uint64_t curr_size = 0;
    while(bytes_finished < size) {
        get_next_ptr_and_size(&state->dev, &src, &curr_ptr,
                              &curr_size, is_list, size, attrs);

        DMADirection dma_dir = (dir == TO_LOCAL) ? DMA_DIRECTION_TO_DEVICE :
                                                   DMA_DIRECTION_FROM_DEVICE;

        err |= pci_dma_rw(&state->dev, curr_ptr, &local[bytes_finished],
            curr_size, dma_dir, *attrs);

        if (err) {
            printf("ERROR: %s Addr 0x%lx\n", __func__, curr_ptr);
            break;
        }
        bytes_finished += curr_size;
        if (err) break;
        /* increment the pointer to the next entry if this one is exhausted */
        src += 16;
    }
    return err;
}

static MemTxAttrs initialize_pasid_attrs_transctl(DCEState *state,
                                uint64_t transctl) {
    /* setup attr for pasid */
    MemTxAttrs attrs = MEMTXATTRS_UNSPECIFIED;
    uint8_t pasid_valid = FIELD_EX64(transctl, DCE_TRANSCTL, TRANSCTL_PASID_V);
    if (pasid_valid) {
        attrs.unspecified = 0;
        attrs.pasid = FIELD_EX64(transctl, DCE_TRANSCTL, TRANSCTL_PASID);
        // printf("Setting pasid to %d\n", attrs.pasid );
        attrs.requester_id = pci_requester_id(&state->dev);
        attrs.secure = 0;
    }
    return attrs;
}

static MemTxAttrs initialize_pasid_attrs(DCEState *state,
                                struct DCEDescriptor *desc) {
    /* setup attr for pasid */
    MemTxAttrs attrs = MEMTXATTRS_UNSPECIFIED;
    if (desc->ctrl & PASID_VALID) {
        attrs.unspecified = 0;
        attrs.pasid = desc->pasid;
        attrs.requester_id = pci_requester_id(&state->dev);
        attrs.secure = 0;
    }
    return attrs;
}

static void dce_memcpy(DCEState *state, struct DCEDescriptor *descriptor,
                        MemTxAttrs * attrs)
{
    uint64_t size = descriptor->operand1;
    uint8_t * local_buffer = malloc(size);

    hwaddr dest = descriptor->dest;
    hwaddr src = descriptor->source;
    bool dest_is_list = (descriptor->ctrl & DEST_IS_LIST) ? true : false;
    bool src_is_list = (descriptor->ctrl & SRC_IS_LIST) ? true : false;
    int err = 0;
    err |= local_buffer_transfer(state, local_buffer, src,
                                size, src_is_list, TO_LOCAL, attrs);
    /* copy to dest from local buffer */
    err |= local_buffer_transfer(state, local_buffer, dest,
                                size, dest_is_list, FROM_LOCAL, attrs);

    complete_workload(state, descriptor, err, 0, size, attrs);
    free(local_buffer);
}

static void dce_memset(DCEState *state, struct DCEDescriptor *descriptor,
                            MemTxAttrs * attrs)
{
    uint64_t pattern1 = descriptor->operand2;
    uint64_t pattern2 = descriptor->operand3;

    bool is_list = (descriptor->ctrl & DEST_IS_LIST) ? true : false;
    int size = descriptor->operand1;
    hwaddr dest = descriptor->dest;
    uint8_t * local_buffer = calloc(1, size);
    int err = 0;

    for (int i = 0; i < size; i++) {
        uint8_t * temp;
        int pattern_offset = i % 16;
        if (pattern_offset < 8) {
            temp = (uint8_t *)&pattern1;
        }
        else {
            pattern_offset -= 8;
            temp = (uint8_t *)&pattern2;
        }
        temp += pattern_offset;
        local_buffer[i] = *temp;
    }


    err |= local_buffer_transfer(state, local_buffer, dest, size,
                                is_list, FROM_LOCAL, attrs);
    complete_workload(state, descriptor, err, 0, size, attrs);
    free(local_buffer);
}

static void dce_memcmp(DCEState *state, struct DCEDescriptor *descriptor,
                            MemTxAttrs * attrs)
{
    uint64_t size = descriptor->operand1;
    bool generate_bitmask = descriptor->operand0 & 1;

    hwaddr dest = descriptor->dest;
    hwaddr src = descriptor->source;
    hwaddr src2 = descriptor->operand2;

    uint8_t * src_local = malloc(size);
    uint8_t * src2_local = malloc(size);
    uint8_t * dest_local = calloc(1, size);

    uint64_t diff_found = 0;
    uint32_t first_diff_index = 0;

    int err = 0;

    bool src_is_list = (descriptor->ctrl & SRC_IS_LIST) ? true : false;
    bool src2_is_list = (descriptor->ctrl & SRC2_IS_LIST) ? true : false;
    bool dest_is_list = (descriptor->ctrl & DEST_IS_LIST) ? true : false;

    err |= local_buffer_transfer(state, src_local, src,
                                size, src_is_list, TO_LOCAL, attrs);
    err |= local_buffer_transfer(state, src2_local, src2,
                                size, src2_is_list, TO_LOCAL, attrs);

    for (int i = 0; i < size; i ++) {
        uint8_t result = src_local[i] ^ src2_local[i];
        if (result != 0) {
            first_diff_index = diff_found ? first_diff_index : i;
            diff_found = 1;
            if (generate_bitmask) {
                dest_local[i] = result;
            } else {
                break;
            }
        }
    }

    if (generate_bitmask)
        err |= local_buffer_transfer(state, dest_local, dest,
                                size, dest_is_list, FROM_LOCAL, attrs);

    else
        err |= local_buffer_transfer(state, (uint8_t *)&diff_found, dest,
                                8, dest_is_list, FROM_LOCAL, attrs);

    first_diff_index = diff_found ? (1 << first_diff_index) : 0;
    complete_workload(state, descriptor, err, 0, first_diff_index, attrs);


    free(src_local);
    free(src2_local);
    free(dest_local);
}

static int dce_crypto(DCEState *state,
                       struct DCEDescriptor *descriptor,
                       unsigned char * src, unsigned char * dest,
                       uint64_t size, int is_encrypt, MemTxAttrs * attrs)
{
#ifdef CONFIG_DCE_CRYPTO
    /* TODO sanity check the size / alignment */
    // printf("In %s\n", __func__);
    int err = 0, ret = 0;
    bool decrypt = (is_encrypt == ENCRYPT) ? 0 : 1;

    uint8_t * key_ids = (uint8_t *)&descriptor->operand3;

    /* Parse operand 0 */
    SecAlgo sec_algo = op0_get_sec_algo(descriptor->operand0);
    SecMode sec_mode = op0_get_sec_mode(descriptor->operand0);

    if (sec_mode==GCM) {
        uint8_t * iv_gcm, * aad;
        hwaddr iv_dma = descriptor->operand2;
        hwaddr aad_dma = descriptor->operand4;
        uint8_t tag[DCE_MAC_LEN];
        uint8_t sec_kid = key_ids[0];
        if(sec_kid >= NUM_KEY_SLOTS){
            return -129;
        }
        /*
         * |  Byte 6 - 7  |   Byte 4 - 5 |
         * |   AAD side   |   IV size    |
         */
        size_t iv_len = extract64(descriptor->operand3, 32, 16);
        size_t aad_len = extract64(descriptor->operand3, 48, 16);
        /* declare local buffers */
        iv_gcm = calloc(iv_len, 1);
        aad = calloc(aad_len, 1);
        if(iv_gcm==NULL || aad ==NULL){
            err=-128;
            goto gcm_cleanup;
        }
        /* copy over IV and AAD */
        local_buffer_transfer(state, iv_gcm, iv_dma,
                                iv_len, false, TO_LOCAL, attrs);
        local_buffer_transfer(state, aad, aad_dma,
                                aad_len, false, TO_LOCAL, attrs);

        if (sec_algo == SM4) {
            // SM4-GCM
            uint8_t key[16]; //16 for SM4
            memcpy(key, state->keys[sec_kid], 16);
            printf("Using SM4-GCM\n");
            ret = dce_sm4_gcm(key, decrypt, iv_gcm, iv_len, aad, aad_len,
                        src, dest, size, tag);
        } else if (sec_algo == AES) {
            // AES-GCM
            uint8_t key[32]; // 32 for AES256
            memcpy(key, state->keys[sec_kid], 32);
            printf("Using AES-GCM\n");
            ret = dce_aes_gcm(key, decrypt, iv_gcm, iv_len, aad, aad_len,
                        src, dest, size, tag);
        } else {
            assert(!"DCE: Unexpected cipher for GCM mode");
            err = -255;
            goto gcm_cleanup;
        }
        if(ret>=0){ /* It worked!
            Write to completion */
            pci_dma_rw(&state->dev, ((uintptr_t)descriptor->completion)+8,
                tag, DCE_MAC_LEN, DMA_DIRECTION_FROM_DEVICE, *attrs);
        }
    gcm_cleanup:
        free(iv_gcm);
        free(aad);
    }
    else if(sec_mode==XTS){
        uint8_t iv_xts[16];
        /*
         * |  Byte 3  |   Byte 2   |   Byte 1  |  Byte 0 |
         * | HASH KID | TWEAKIV ID | TWEAK KID | SEC KID |
         */
        uint8_t sec_kid = key_ids[0];
        uint8_t tweak_kid = key_ids[1];
        uint8_t iv_kid = key_ids[2];
        if(  sec_kid   >= NUM_KEY_SLOTS
          || tweak_kid >= NUM_KEY_SLOTS
          || iv_kid    >= NUM_KEY_SLOTS){
            return -129;
        }
        /* setting up IV */
        memcpy(iv_xts, state->keys[iv_kid], 16);

        if (sec_algo==SM4) {
            // SM4-XTS
            printf("Using SM4-XTS\n");
            /* setup the encryption keys*/
            uint8_t key[32];
            memcpy(key, state->keys[sec_kid], 16);
            memcpy(key + 16, state->keys[tweak_kid], 16);

            ret = dce_sm4_xts(key, decrypt, iv_xts, src, dest, size);
        }
        else if (sec_algo == AES){
            // AES-XTS
            printf("Using AES-XTS\n");
            /* setup the encryption keys*/
            uint8_t key[64];
            memcpy(key, state->keys[sec_kid], 32);
            memcpy(key + 32, state->keys[tweak_kid], 32);

            ret = dce_aes_xts(key, decrypt, iv_xts, src, dest, size);
        }
    } else {
        assert(!"DCE: unexpected crypto mode");
    }

    if (ret < 0) {
        printf("ERROR: Encrypt / Decrypt failed!\n");
        return -1;
    }
    return err;
#else
    qemu_log_mask(LOG_UNIMP, "Crypto not implemented in DCE");
    return -1;
#endif
}

static int dce_compress_decompress(struct DCEDescriptor *descriptor,
                                   const char * src, char * dst,
                                   size_t src_size, size_t * dst_size, int dir)
{
#ifdef CONFIG_DCE_COMPRESSION
    int err = 0;
    /* bit 1-3 in opernad 0 specify the compression format */
    //int comp_format = (descriptor->operand0 >> 1) & 0x7;
    int comp_format = op0_get_comp_format(descriptor->operand0);
    switch(comp_format) {
        case RLE:
            break;
        case Snappy:
            if (dir == COMPRESS) {
                printf("Compressing using Snappy!");
                err = snappy_compress(src, src_size, dst, dst_size);
            } else {
                printf("Decompressing using Snappy!\n");
                err = snappy_uncompress(src, src_size, dst, dst_size);
            }
            break;
        case LZ4:
            if (dir == COMPRESS) {
                printf("Compressing using LZ4!\n");
                *dst_size = LZ4_compress_default(src, dst, src_size, *dst_size);
            } else {
                printf("Decompressing using LZ4!\n");
                *dst_size = LZ4_decompress_safe(src, dst, src_size, *dst_size);
            }
            break;
        case GZIP:
            if (dir == COMPRESS) {
                printf("Compressing using GZIP!\n");
                err = compress((Bytef *)dst, dst_size, (Bytef *)src, src_size);
            } else {
                printf("Decompressing using GZIP!\n");
                err = uncompress((Bytef *)dst, dst_size,(Bytef *)src, src_size);
            }
            break;
        case ZSTD:
            if (dir == COMPRESS) {
                printf("Compressing using ZSTD!\n");
                *dst_size = ZSTD_compress(dst, *dst_size, src, src_size, 1);
            } else {
                printf("Decompressing using ZSTD!\n");
                *dst_size = ZSTD_decompress(dst, *dst_size, src, src_size);
            }
            break;
        default:
            return -1;
    }
    if(err) printf("%s: ERROR: %d\n", __func__, err);
    return err;
#else  // CONFIG_DCE_COMPRESSION
    return -1;
#endif // CONFIG_DCE_COMPRESSION
}

/* CRC specific, move to a seperate file ? */

// Mode can be one of followings;
#define CRC8 0

uint64_t const Mask[8] = { 0xFF, 0xFFFF, 0xFFFFFF, 0xFFFFFFFF, 0xFFFFFFFFFF, 0xFFFFFFFFFFFF, 0xFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF };
uint64_t const Msbcheck[8] = { 0x80, 0x8000, 0x800000, 0x80000000, 0x8000000000, 0x800000000000, 0x80000000000000, 0x8000000000000000 };
uint8_t const Shifter[8] = { 0, 8, 16, 24, 32, 40, 48, 56 };

static void reflect8(uint8_t * buffer) {
        /*
         * bit 7 is swapped with bit 0
         * bit 6 is swapped with bit 1
         * bit 5 is swapped with bit 2
         * bit 4 is swapped with bit 3
         */
        uint8_t b = *buffer;
        b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
        b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
        b = (b & 0xAA) >> 1 | (b & 0x55) << 1;
        *buffer = b;
}

static void reflect(uint64_t* Inp, uint8_t Width)
{
    uint64_t tmp = ((uint64_t)Width / 8) - 1;
    uint64_t mask = Msbcheck[tmp];
    tmp = *Inp;
    *Inp = 0;
    while (Width--)
    {
        if (tmp & 1L)
            *Inp |= mask;
        tmp >>= 1;
        mask >>= 1;
    }
    return;
}

static void reflect_buffer(uint8_t * buffer, size_t size) {
    for (int i = 0; i < size; i ++) {
        reflect8(buffer + i);
    }
}

static void CreateCRCtable(uint64_t* CrcTable, uint64_t Polynomial, uint8_t Width)
{
    printf("Generating CRC table with width %u, Polynomial 0x%lx\n", Width, Polynomial);
    uint64_t index;
    uint64_t value;
    uint8_t cnt;
    uint8_t mode = Width / 8 - 1;

    for (index = 0; index < 256; index++)
    {
        value = ((index << Shifter[mode]) & Mask[mode]);
        cnt = 8;
        while (cnt--)
        {
            value = ((value & Msbcheck[mode]) == 0) ? (value << 1) : (value << 1) ^ Polynomial;
            value &= Mask[mode];
        }
        CrcTable[index] = value;
    }

    printf("Printing CRC table:\n");
    for(int i = 0; i < 32; i++) {
        for(int j = 0; j < 8; j++) {
            printf("0x%lx ", CrcTable[i * 8 + j]);
        }
        printf("\n");
    }
    printf("\n");
}

static uint64_t CalculateCRC(uint8_t* Buffer, uint64_t Length, uint64_t* CrcTable,
                      uint8_t Width, uint64_t initValue, uint64_t XORout)
{
    uint64_t crc = initValue;
    uint8_t mode = Width / 8 - 1;
    uint8_t index;
    while (Length--)
    {
        index = (uint8_t)((crc >> Shifter[mode]) ^ *Buffer++);
        crc = (mode == CRC8) ? (CrcTable[index]) : ((crc << 8) ^ CrcTable[index]);
    }
    return ((crc ^ XORout) & Mask[mode]);
}

static void dce_crc(DCEState *state, struct DCEDescriptor *descriptor,
                                MemTxAttrs * attrs)

{
    /* TODO: add error */
    /* parse from the descriptor */
    uint16_t crc_ctl = descriptor->operand0;
    uint64_t polynomial = descriptor->operand1;
    uint64_t init_value = descriptor->operand2;
    uint64_t xor_value = descriptor->operand3;
    uint64_t job_control = descriptor->operand4;

    int err = 0;

    hwaddr dest = descriptor->dest;
    hwaddr src = descriptor->source;

    /* extract fields */
    uint64_t byte_width = (FIELD_EX16(crc_ctl, CRC_CTRL, WIDTH) + 1);
    uint64_t bit_width = byte_width * 8;
    bool reflect_in = FIELD_EX16(crc_ctl, CRC_CTRL, REFLECT_IN);
    bool reflect_out = FIELD_EX16(crc_ctl, CRC_CTRL, REFLECT_OUT);
    uint8_t pad = FIELD_EX16(crc_ctl, CRC_CTRL, PAD_BIT);
    pad = pad ? 0xf : 0x0;
    polynomial = (bit_width == 64) ? (polynomial & ~(0ULL))
                                   : (polynomial & ((1ULL << bit_width) - 1));

    size_t size = FIELD_EX64(job_control, JOB_CTRL, NUM_BYTES);
    size_t size_adjusted = (size % byte_width == 0)
                            ? size
                            : (size + (byte_width - (size % byte_width)));

    /* Pad zeros if needed */
    uint8_t * src_local = malloc(size_adjusted);
    if (size_adjusted > size)
        /* Pad if needed */
        memset(src_local + size, pad, size_adjusted - size);
    bool src_is_list = (descriptor->ctrl & SRC_IS_LIST) ? true : false;

    err |= local_buffer_transfer(state, (uint8_t *)src_local, src,
                        size, src_is_list, TO_LOCAL, attrs);

    /* perform the memcpy if using opcode DCE_OPCODE_MEMCPY_CRC_GEN */
    if (descriptor->opcode == DCE_OPCODE_MEMCPY_CRC_GEN) {
        bool dest_is_list = (descriptor->ctrl & DEST_IS_LIST) ? true : false;
        err |= local_buffer_transfer(state, src_local, dest,
                            size, dest_is_list, FROM_LOCAL, attrs);
    }

    /* Reflect input if specified */
    if (reflect_in)
        reflect_buffer(src_local, size);

    uint64_t crc_table[256];
    /* Fill up the CRC table */
    CreateCRCtable(crc_table, polynomial, bit_width);

    uint64_t crc =
        CalculateCRC(src_local, size_adjusted, crc_table, bit_width, init_value, xor_value);

    /* Reflect output if specified */
    if (reflect_out) {
        reflect(&crc, bit_width);
    }

    complete_workload(state, descriptor, err, 0, size_adjusted, attrs);
    /* write the CRC into completion */
    if (!err)
        pci_dma_rw(&state->dev, descriptor->completion + 8,
        &crc, 8, DMA_DIRECTION_FROM_DEVICE, *attrs);
}

#define MAKE128CONST(hi,lo) ((((__uint128_t)hi << 64) | lo))

static uint64_t extract_bytes(uint8_t * reg, int lo, int hi) {
    uint64_t result = 0;
    int shift = 0;
    for (int curr = hi; curr >= lo; curr--) {
        result += (reg[curr] << shift);
        shift += 8;
    }
    return result;
}

static uint64_t extract_at(uint8_t * pi, PIF_encoding PIF, uint64_t at_mask){
    uint64_t ret = 0;
    switch(PIF) {
        case _16GB:
            // at = extract_bytes(pi, 2, 3)
            ret = extract_bytes(pi, 2, 3);
            break;
        case _32GB:
            // at = extract_bytes(pi, 4, 5)
            ret = extract_bytes(pi, 4, 5);
            break;
        case _64GB:
            // at = extract_bytes(pi, 8, 9)
            ret = extract_bytes(pi, 8, 9);
            break;
        default:
            break;
    }
    return (ret & at_mask);
}

static __uint128_t extract_strt(uint8_t * pi, PIF_encoding PIF,
                                    __uint128_t st_rt_mask){
    __uint128_t ret = 0;
    uint64_t ret_lo = 0;
    uint64_t ret_hi = 0;
    switch(PIF) {
        case _16GB:
            // st = extract_bytes(pi, 4, 7)
            ret_lo = extract_bytes(pi, 4, 7);
            break;
        case _32GB:
            // st = extract_bytes(pi, 6, 15)
            ret_lo = extract_bytes(pi, 8, 15);
            ret_hi = extract_bytes(pi, 6, 7);
            break;
        case _64GB:
            // st = extract_bytes(pi, 10, 15)
            ret_lo = extract_bytes(pi, 10, 15);
            break;
        default:
            break;
    }
    ret = MAKE128CONST(ret_hi, ret_lo);
    return (ret & st_rt_mask);
}

static uint64_t extract_guard(uint8_t * pi, PIF_encoding PIF) {
    uint64_t ret = 0;
    switch(PIF) {
        case _16GB:
            ret = extract_bytes(pi, 0, 1);
            break;
        case _32GB:
            ret = extract_bytes(pi, 0, 3);
            break;
        case _64GB:
            ret = extract_bytes(pi, 0, 7);
            break;
        default:
            break;
    }
    return ret;
}

static void insert_bytes(uint8_t * buffer, int lo, int hi, uint8_t * src) {
    for (int index = lo; index <= hi; index++) {
        buffer[index] = *src;
        src++;
    }
}

static void form_pi(uint8_t * pi, PIF_encoding PIF, uint64_t guard, uint64_t at,
                         __uint128_t st, __uint128_t rt) {
    __uint128_t st_rt = st | rt;
    switch(PIF) {
        case _16GB:
            insert_bytes(pi, 0, 1, (uint8_t *)&guard);
            insert_bytes(pi, 2, 3, (uint8_t *)&at);
            insert_bytes(pi, 4, 7, (uint8_t *)&st_rt);
            break;
        case _32GB:
            insert_bytes(pi, 0, 3, (uint8_t *)&guard);
            insert_bytes(pi, 4, 5, (uint8_t *)&at);
            insert_bytes(pi, 6, 16, (uint8_t *)&st_rt);
            break;
        case _64GB:
            insert_bytes(pi, 0, 7, (uint8_t *)&guard);
            insert_bytes(pi, 8, 9, (uint8_t *)&at);
            insert_bytes(pi, 10, 15, (uint8_t *)&st_rt);
            break;
        default:
            break;
    }
}

static void dce_pi(DCEState *state, struct DCEDescriptor *descriptor,
                                MemTxAttrs * attrs)
{
    uint16_t fmt_info = descriptor->operand0;
    uint16_t STS = FIELD_EX16(fmt_info, FMT_INFO, _STS);
    uint16_t ATS = FIELD_EX16(fmt_info, FMT_INFO, _ATS);
    uint16_t PIF = FIELD_EX16(fmt_info, FMT_INFO, _PIF);
    uint16_t LBAS = FIELD_EX16(fmt_info, FMT_INFO, _LBAS);
    uint64_t src_pi_hi = descriptor->operand2;
    uint64_t src_pi_lo = descriptor->operand1;
    uint64_t dst_pi_hi = descriptor->operand4;
    uint64_t dst_pi_lo = descriptor->operand3;
    uint8_t opcode = descriptor->opcode;

    dma_addr_t bfr1 = descriptor->source;
    dma_addr_t bfr2 = descriptor->dest;

    __uint128_t src_pi_ctl =
        MAKE128CONST(src_pi_hi, src_pi_lo);
    __uint128_t dst_pi_ctl =
        MAKE128CONST(dst_pi_hi, dst_pi_lo);

    uint8_t GVC = extract64(src_pi_hi, 32, 1);
    uint8_t ATC = extract64(src_pi_hi, 33, 1);
    uint8_t PRC = extract64(src_pi_hi, 34, 1);
    uint8_t STC = extract64(src_pi_hi, 35, 1);
    uint8_t A1E = extract64(src_pi_hi, 36, 1);

    uint8_t ATI = extract64(dst_pi_hi, 32, 1);
    uint8_t PRI = extract64(dst_pi_hi, 33, 1);
    uint8_t STI = extract64(dst_pi_hi, 34, 1);
    uint64_t dst_reserved = extract64(dst_pi_hi, 35, 6);

    Protection_type PT = extract64(src_pi_hi, 46, 2);

    PI_error_codes err = NO_PI_ERROR;

    /* initialize the variables used for completion early */
    size_t block_size = (LBAS == 0) ? 512 : 4096;
    int num_lba_processed = 0;

    if (((LBAS != 0) && (LBAS != 1)) ||
        (PIF == PIF_RESERVED) ||
        (ATS > 16) ||
        ((PIF == _16GB) && (STS > 32)) ||
        ((PIF == _32GB) && (STS < 16 || STS > 64)) ||
        ((PIF == _64GB) && (STS > 48)) ||
        (dst_reserved != 0) ||
        ((ATC == 1) && (ATS == 0)) ||
        ((STC == 1) && (STS == 0)) ||
        ((PRC == 1) && (STS == 32) && (PIF == _16GB)) ||
        ((PRC == 1) && (ATS == 64) && (PIF == _32GB)) ||
        ((PRC == 1) && (ATS == 48) && (PIF == _64GB)) ||
        ((ATI == 1) && (ATS == 0)) ||
        ((STI == 1) && (STS == 0)) ||
        ((PRI == 1) && (STS == 32) && (PIF == _16GB)) ||
        ((PRI == 1) && (ATS == 64) && (PIF == _32GB)) ||
        ((PRI == 1) && (ATS == 48) && (PIF == _64GB))) {
        err = INVALID_PI_DESCRIPTOR;
        goto finish_pi;
    }

    __uint128_t _96bitmask = MAKE128CONST(0xffffffff, 0xFFFFFFFFFFFFFFFF);

    uint64_t crc_poly, pi_size, at_mask;
    __uint128_t ref_tag_mask, st_tag_mask;
    uint8_t crc_width = 0;

    if (PIF == _16GB) {
        crc_poly = 0x18BB7;
        pi_size = 8;
        ref_tag_mask = (STS == 32) ? 0 : ((1 << (32 - STS)) - 1);
        st_tag_mask = 0xFFFFFFFF ^ ref_tag_mask;
        at_mask = (1 << ATS) - 1;
        crc_width = 16;
    } else if (PIF == _32GB) {
        crc_poly = 0x1EDC6F41;
        pi_size = 16;
        ref_tag_mask = (STS == 64) ? 0 : ((1 << (64 - STS)) - 1);
        st_tag_mask = _96bitmask ^ ref_tag_mask;
        at_mask = (1 << ATS) - 1;
        crc_width = 32;
    } else if (PIF == _64GB) {
        crc_poly = 0xAD93D23594C93659ULL;
        pi_size = 16;
        ref_tag_mask = (STS == 48) ? 0 : ((1 << (48 - STS)) - 1);
        st_tag_mask = 0xFFFFFFFFFFFF ^ ref_tag_mask;
        at_mask = (1 << ATS) - 1;
        crc_width = 64;
    }

    uint64_t crc_table[256];
    /* Fill up the CRC table TODO: figureing out the width*/
    CreateCRCtable(crc_table, crc_poly, crc_width);

    __uint128_t exp_st, exp_rt, dst_st, dst_rt, st, rt;
    uint16_t exp_at, dst_at, at, num_lbas;

    // exp_at = src_pi_ctl.ELBAT & at_mask
    exp_at = extract64(src_pi_hi, 48, 16);
    exp_at &= at_mask;
    // exp_st = src_pi_ctl[95:0] & st_tag_mask
    exp_st = src_pi_ctl & st_tag_mask;
    // exp_rt = src_pi_ctl[95:0] & ref_tag_mask
    exp_rt = src_pi_ctl & ref_tag_mask;
    // dst_at = dst_pi_ctl.LBAT & at_mask
    dst_at = extract64(dst_pi_hi, 48, 16);
    dst_at &= at_mask;
    // dst_st = dst_pi_ctl[95:0] & st_tag_mask
    dst_st = dst_pi_ctl & st_tag_mask;
    // dst_rt = dst_pi_ctl[95:0] & ref_tag_mask
    dst_rt = dst_pi_ctl & ref_tag_mask;
    // num_lbas = (dst_pi_ctl.num_lba[15:9] << 9)
    // num_lbas |= src_pi_ctl.num_lba[8:0]
    num_lbas = (extract64(dst_pi_hi, 37, 9) << 9) + extract64(src_pi_hi, 37, 9);

    uint8_t * data = malloc(block_size);
    uint8_t * source_pi = malloc(pi_size);
    uint8_t * dst_pi = malloc(pi_size);
    uint64_t source_crc, source_at, source_guard;
    __uint128_t source_st, source_rt;
    bool skip_checks = false;

    for (num_lba_processed = 0; num_lba_processed < num_lbas; num_lba_processed++) {
        pci_dma_rw(&state->dev, bfr1, data, block_size,
                DMA_DIRECTION_TO_DEVICE, *attrs);
        bfr1 += block_size;
        if (opcode == DCE_OPCODE_DIF_CHK ||
            opcode == DCE_OPCODE_DIF_UPD ||
            opcode == DCE_OPCODE_DIF_STRP) {
            pci_dma_rw(&state->dev, bfr1, source_pi, pi_size,
                DMA_DIRECTION_TO_DEVICE, *attrs);
            bfr1 += pi_size;
        }
        if (opcode == DCE_OPCODE_DIX_CHK) {
            pci_dma_rw(&state->dev, bfr2, source_pi, pi_size,
                DMA_DIRECTION_TO_DEVICE, *attrs);
            bfr2 += pi_size;
        }
        source_crc = CalculateCRC(data, block_size, crc_table, crc_width, 0, 0);
        // f. If opcode == dif_chk || opcode == dif_upd || opcode == dif_strp || dix_chk
        if (opcode == DCE_OPCODE_DIF_CHK ||
            opcode == DCE_OPCODE_DIF_UPD ||
            opcode == DCE_OPCODE_DIX_CHK ||
            opcode == DCE_OPCODE_DIF_STRP) {
            source_at = extract_at(source_pi, PIF, at_mask);
            source_st = extract_strt(source_pi, PIF, st_tag_mask);
            source_rt = extract_strt(source_pi, PIF, ref_tag_mask);
            source_guard = extract_guard(source_pi, PIF);
            // If (source_at == all 1’s && PT != TYPE3) ||
            // (source_at == all 1’s && source_rt == all 1’s && PT == TYPE3)
            // skip_checks = 1
            if (((source_at = at_mask) && (PT != TYPE_3)) ||
                ((source_at = at_mask) && (source_rt == ref_tag_mask &&
                (PT == TYPE_3)))) {
                skip_checks = true;
            }
            // If skip_checks && src_pi_ctl.A1E == 1
            if (skip_checks && (A1E == 1)) {
                // Cause = “Invalid PI”
                err = INVALID_PI;
                goto clean_up_and_finish_pi;
            }
            // if src_pi_ctl.GVC == 1 && skip_checks == 0
            if (!skip_checks && (GVC == 1)) {
                if (source_crc != source_guard) {
                    err = GUARD_CHECK_FAILED;
                    goto clean_up_and_finish_pi;
                }
            }
            // if src_pi_ctl.ATC == 1 && skip_checks == 0
            if (!skip_checks && (ATC == 1)) {
                if (source_at != exp_at) {
                    err = APPLICATION_TAG_CHECK_FAILED;
                    goto clean_up_and_finish_pi;
                }
            }
            // if src_pi_ctl.PRC == 1 && skip_checks == 0
            if (!skip_checks && (PRC == 1)) {
                if (source_rt != exp_rt) {
                    err = REFERENCE_TAG_CHECK_FAILED;
                    goto clean_up_and_finish_pi;
                }
            }
            // if src_pi_ctl.STC == 1 && skip_checks == 0
            if (!skip_checks && (STC == 1)) {
                if (source_st != exp_st) {
                    err = STORAGE_TAG_CHECK_FAILED;
                    goto clean_up_and_finish_pi;
                }
            }
            if (!skip_checks) {
                exp_rt = (exp_rt + 1) & ref_tag_mask;
            }
        }
        // g. If opcode == dif_strp || opcode == dif_upd || op == dif_gen
        if (opcode == DCE_OPCODE_DIF_GEN ||
            opcode == DCE_OPCODE_DIF_UPD ||
            opcode == DCE_OPCODE_DIF_STRP) {
            pci_dma_rw(&state->dev, bfr2, data, block_size,
                DMA_DIRECTION_FROM_DEVICE, *attrs);
            bfr2 += block_size;
        }
        // h. If opcode == dif_upd || opcode == dif_gen || opcode == dix_gen
        if (opcode == DCE_OPCODE_DIF_GEN ||
            opcode == DCE_OPCODE_DIF_UPD ||
            opcode == DCE_OPCODE_DIX_GEN) {
            source_guard = source_crc;
            at = ATI ? dst_at : exp_at;
            rt = PRI ? dst_rt : exp_rt;
            st = STI ? dst_st : exp_st;
            form_pi(dst_pi, PIF, source_guard, at, st, rt);
            // write(desc.bfr2, pi_size, dst_pi);
            pci_dma_rw(&state->dev, bfr2, dst_pi, pi_size,
                DMA_DIRECTION_FROM_DEVICE, *attrs);
            bfr2 += pi_size;
            dst_rt = (dst_rt + 1) & ref_tag_mask;
        }
    }
clean_up_and_finish_pi:
    /* free the memories we have allocated */
    free(data);
    free(source_pi);
    free(dst_pi);
finish_pi:
    /* populate the completion */
    complete_workload(state, descriptor, err, 0,
        num_lba_processed * block_size, attrs);

}

static void dce_data_process(DCEState *state, struct DCEDescriptor *descriptor,
                                MemTxAttrs * attrs)
{
    uint64_t job_size = descriptor->operand1;
    uint64_t src_size = job_size;
    uint64_t dest_size;
    size_t post_process_size, err = 0;
    /* create local buffers used for LZ4 */
    char * src_local = NULL;
    char * dest_local = NULL;

    hwaddr dest = descriptor->dest;
    hwaddr src = descriptor->source;

    bool dest_is_list = (descriptor->ctrl & DEST_IS_LIST) ? true : false;
    bool src_is_list = (descriptor->ctrl & SRC_IS_LIST) ? true : false;

#ifdef CONFIG_DCE_CRYPTO
    const bool is_enc = descriptor->opcode == DCE_OPCODE_ENCRYPT;
    const bool is_dec = descriptor->opcode == DCE_OPCODE_DECRYPT;
    const bool is_crypto = is_enc || is_dec;
    const SecMode mode =  op0_get_sec_mode(descriptor->operand0);

    if (is_crypto){
        /* crypto, dest size == src size */
        if(mode == XTS){ //XTS inspired XEX mode
            //ciphertext is larger than cleartext
            const size_t ciph_size = (job_size+15)&~0xF;
            if(is_enc)
                dest_size = ciph_size;
            else if(is_dec){
                src_size = ciph_size;
                dest_size = job_size;
            }
        }
        else
            dest_size = src_size;
    }
    else
#endif
    {
        /* Compression operations, dest has its own size */
        dest_size = descriptor->operand2;
    }

    /* alloc buffers required for job */
    /* from now on, exit through cleanup: */
    src_local  = malloc(src_size);
    dest_local = calloc(dest_size, 1);
    post_process_size = dest_size;

    if(src_local == NULL || dest_local == NULL) {
        err = -1;
        goto error;
    }

    /* copy to local buffer */

    local_buffer_transfer(state, (uint8_t *)src_local, src,
                        src_size, src_is_list, TO_LOCAL, attrs);

    /* perform compression / decompression */
    switch(descriptor->opcode)
    {
        case DCE_OPCODE_COMPRESS:
            err |= dce_compress_decompress(descriptor, src_local, dest_local,
                                           src_size, &post_process_size,
                                           COMPRESS);
            printf("Compressed - %ld bytes\n", post_process_size);
            break;
        case DCE_OPCODE_DECOMPRESS:
            err |= dce_compress_decompress(descriptor, src_local, dest_local,
                                           src_size, &post_process_size,
                                           DECOMPRESS);
            printf("Decompressed - %ld bytes\n", post_process_size);
            break;
        case DCE_OPCODE_ENCRYPT:
            err |= dce_crypto(state, descriptor, (uint8_t *)src_local,
                       (uint8_t *)dest_local, job_size, ENCRYPT, attrs);
            printf("Encrypted %ld bytes\n", post_process_size);
            break;
        case DCE_OPCODE_DECRYPT:

            err |= dce_crypto(state, descriptor, (uint8_t *)src_local,
                       (uint8_t *)dest_local, job_size, DECRYPT, attrs);
            printf("Decrypted %ld bytes\n", post_process_size);
            break;
        default:
            /* TODO add error code */
            err |= -1;
            break;
    }

    err |= (post_process_size == 0 || post_process_size > dest_size);
    if (err) goto error;
    /* copy back the results */

    local_buffer_transfer(state, (uint8_t *)dest_local, dest,
                        post_process_size, dest_is_list, FROM_LOCAL, attrs);
    goto cleanup;

error:
    printf("ERROR: error has occured, cleaning up!");
cleanup:
    complete_workload(state, descriptor, err, 0, post_process_size, attrs);
    free(src_local);
    free(dest_local);
}

static void dce_load_key(DCEState *state, struct DCEDescriptor *descriptor,
        MemTxAttrs * attrs)
{
    // printf("In %s\n", __func__);
    uint8_t keyid = descriptor->dest;
    if(keyid >= NUM_KEY_SLOTS){
        //Write error in completion
        complete_workload(state, descriptor,
                -1, 0, 0, /* error, spec, data */
                attrs);
        return;
    }

    unsigned char * key = state->keys[keyid];
    uint64_t * src = (uint64_t *)descriptor->source;

    pci_dma_rw(&state->dev, (dma_addr_t)src, key, DCE_AES_KEYLEN,
                DMA_DIRECTION_TO_DEVICE, *attrs);
    complete_workload(state, descriptor, 0, 0, DCE_AES_KEYLEN, attrs);
}

static void dce_clear_key(DCEState *state, struct DCEDescriptor *descriptor,
        MemTxAttrs * attrs)
{
    // printf("In %s\n", __func__);
    uint8_t keyid = descriptor->dest;
    if(keyid >= NUM_KEY_SLOTS){
        complete_workload(state, descriptor,
                -1, 0, 0, /* error, spec, data */
                attrs);
        return;
    }
    unsigned char * key = state->keys[keyid];
    memset(key, 0, DCE_AES_KEYLEN);
    complete_workload(state, descriptor, 0, 0, DCE_AES_KEYLEN, attrs);
}

static void finish_descriptor(DCEState *state, int WQ_id,
                hwaddr descriptor_address, uint64_t transctl)
{
    struct DCEDescriptor descriptor;
    MemTxAttrs transctl_attrs = initialize_pasid_attrs_transctl(state, transctl);
    MemTxResult ret = pci_dma_rw(&state->dev, descriptor_address,
                &descriptor, 64, DMA_DIRECTION_TO_DEVICE, transctl_attrs);
    // TODO: Error on misaligned completion cat1?
    MemTxAttrs desc_attrs = initialize_pasid_attrs(state, &descriptor);
    bool is_priviledged =
        (FIELD_EX64(transctl, DCE_TRANSCTL ,TRANSCTL_SUPV) == 1);
    MemTxAttrs * attrs_to_use = is_priviledged ? &desc_attrs : &transctl_attrs;

    // printf("CTRL and PASID: 0x%x, 0x%x\n", descriptor.ctrl, descriptor.pasid);

    //TODO: I think we can do better than pretend it did not happen: Cat2 (or Cat1?)
    if (ret) printf("%s: ERROR: %x\n",__func__, ret);
    printf("Processing descriptor with opcode %d\n", descriptor.opcode);

    switch (descriptor.opcode) {
        case DCE_OPCODE_MEMCPY:
            dce_memcpy(state, &descriptor, attrs_to_use); break;
        case DCE_OPCODE_MEMSET:
            dce_memset(state, &descriptor, attrs_to_use); break;
        case DCE_OPCODE_MEMCMP:
            dce_memcmp(state, &descriptor, attrs_to_use); break;
        // case DCE_OPCODE_COMPRESS:
        // case DCE_OPCODE_DECOMPRESS:
        case DCE_OPCODE_ENCRYPT:
        case DCE_OPCODE_DECRYPT:
        // case DCE_OPCODE_DECRYPT_DECOMPRESS:
        // case DCE_OPCODE_COMPRESS_ENCRYPT:
            dce_data_process(state, &descriptor, attrs_to_use); break;
        case DCE_OPCODE_LOAD_KEY:
            dce_load_key(state, &descriptor, attrs_to_use); break;
        case DCE_OPCODE_CLEAR_KEY:
            dce_clear_key(state, &descriptor, attrs_to_use); break;
        case DCE_OPCODE_CRC_GEN:
        case DCE_OPCODE_MEMCPY_CRC_GEN:
            dce_crc(state, &descriptor, attrs_to_use); break;
        case DCE_OPCODE_DIF_CHK:
        case DCE_OPCODE_DIF_GEN:
        case DCE_OPCODE_DIF_UPD:
        case DCE_OPCODE_DIF_STRP:
        case DCE_OPCODE_DIX_CHK:
        case DCE_OPCODE_DIX_GEN:
            dce_pi(state, &descriptor, attrs_to_use); break;
    }
    /* interupt only in priviledged mode */
    if (interrupt_on_completion(state, &descriptor) && is_priviledged)
        dce_raise_interrupt(state, WQ_id, DCE_INTERRUPT_DESCRIPTOR_COMPLETION);
}

#define TYPE_PCI_DCE_DEVICE "dce"
#define TYPE_PCI_DCEVF_DEVICE "dcevf"

DECLARE_INSTANCE_CHECKER(DCEState, DCE, TYPE_PCI_DCE_DEVICE)

// static void dce_obj_uint64(Object *obj, Visitor *v, const char *name,
//                            void *opaque, Error **errp)
// {
//     uint64_t *val = opaque;

//     visit_type_uint64(v, name, val, errp);
// }


static uint64_t dce_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    printf("in %s, addr: 0x%lx\n", __func__, addr);
    assert(aligned(addr, size));

    DCEState *s = (DCEState*) opaque;

    if (size == 0 || size > 8 || (addr & (size - 1)) != 0) {
        /* Unsupported MMIO alignment or access size */
        return 0;
    }

    if (addr + size > sizeof(s->regs_rw)) {
        /* Unsupported MMIO access location. */
        return 0;
    }

    uint64_t result = 0;
    uint32_t page = addr / DCE_PAGE_SIZE;
    addr = addr % DCE_PAGE_SIZE;

    if (size == 1) {
        result = s->regs_rw[page][addr];
    } else if (size == 2) {
        result = lduw_le_p(&s->regs_rw[page][addr]);
    } else if (size == 4) {
        result = ldl_le_p(&s->regs_rw[page][addr]);
    } else if (size == 8) {
        result = ldq_le_p(&s->regs_rw[page][addr]);
    }
    return result;
}

static void dce_mmio_write(void *opaque, hwaddr addr, uint64_t val,
                    unsigned size)
{
    // printf("in %s, addr: 0x%lx, val: 0x%lx\n", __func__, addr, val);

    DCEState *s = (DCEState*) opaque;

    uint32_t page = addr / DCE_PAGE_SIZE;
    addr = addr % DCE_PAGE_SIZE;
    uint32_t exec = 0;
    // uint32_t busy = 0;

    // uint32_t regb = (addr + size - 1) & ~3;
    // printf("regb 0x%x, addr 0x%lx, page %d\n", regb, addr, page);
    if (size == 0 || size > 8 || (addr & (size - 1)) != 0) {
        /* Unsupported MMIO alignment or access size */
        return;
    }

    if (addr + size > sizeof(s->regs_rw)) {
        /* Unsupported MMIO access location. */
        return;
    }

    if (page == WQMCC) {
        /* WQMCC page */
    }
    else if (WQMCC < page && page <= NUM_WQ) {
        /* WQCR pages */
        if (addr == DCE_REG_WQCR) {
            exec |= BIT(DCE_EXEC_NOTIFY);
        }
    }
    else if (page == GLOB_CONF) {
        /* Global config page */
        if (addr == DCE_REG_FUNC_WQ_PROCESSING_CTL) {
            exec |= BIT(DCE_EXEC_RESET_ARB_WEIGHT);
        }
    }

    qemu_mutex_lock(&s->core_lock);
    if (size == 1) {
        uint8_t ro = s->regs_ro[page][addr];
        uint8_t wc = 0;
        uint8_t rw = s->regs_rw[page][addr];
        s->regs_rw[page][addr] = ((rw & ro) | (val & ~ro)) & ~(val & wc);
    } else if (size == 2) {
        uint16_t ro = lduw_le_p(&s->regs_ro[page][addr]);
        uint16_t wc = 0;
        uint16_t rw = lduw_le_p(&s->regs_rw[page][addr]);
        stw_le_p(&s->regs_rw[page][addr], ((rw & ro) | (val & ~ro)) & ~(val & wc));
    } else if (size == 4) {
        uint32_t ro = ldl_le_p(&s->regs_ro[page][addr]);
        uint32_t wc = 0;
        uint32_t rw = ldl_le_p(&s->regs_rw[page][addr]);
        stl_le_p(&s->regs_rw[page][addr], ((rw & ro) | (val & ~ro)) & ~(val & wc));
    } else if (size == 8) {
        uint64_t ro = ldq_le_p(&s->regs_ro[page][addr]);
        uint64_t wc = 0;
        uint64_t rw = ldq_le_p(&s->regs_rw[page][addr]);
        stq_le_p(&s->regs_rw[page][addr], ((rw & ro) | (val & ~ro)) & ~(val & wc));
    }
    qemu_mutex_unlock(&s->core_lock);
    // printf("Exec %d\n", exec);
    if (exec) {
        /* set the execute flag on the pf */
        qatomic_or(&(s->pfstate->core_exec), exec);
        // printf("Signaling conditioon\n");
        qemu_cond_signal(&(s->pfstate->core_cond));
    }
}

static const MemoryRegionOps dce_mmio_ops = {
    .read  = dce_mmio_read,
    .write = dce_mmio_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .impl = {
        .min_access_size = 1,
        .max_access_size = 8,
        .unaligned = false
    },
};

static void set_ready_to_run_all_places(DCEState * state, int WQ_id, int val)
{
    /* should already hold lock */
    uint32_t WQCR = ldl_le_p(&state->regs_rw[WQ_id+1][DCE_REG_WQCR]);
    WQCR = FIELD_DP32(WQCR, DCE_WQCR, STATUS, val);
    stl_le_p(&state->regs_rw[WQ_id+1][DCE_REG_WQCR], WQCR);

    uint64_t WQRUNSTS = ldq_le_p(&state->regs_rw[0][DCE_REG_WQRUNSTS]);
    WQRUNSTS = deposit64(WQRUNSTS, WQ_id, 1, val);
    stq_le_p(&state->regs_rw[0][DCE_REG_WQRUNSTS], WQRUNSTS);

    /* FIXME lock for global config page? */
    uint64_t WQRUNSTS_GLOB =
        ldq_le_p(&state->regs_rw[GLOB_CONF][DCE_REG_FUNC_WQ_RUN_STS]);
    int Fn = state->isVF ? state->vfnum + 1 : 0;
    /* index into the function */
    WQRUNSTS_GLOB += (Fn * 8);
    WQRUNSTS = deposit64(WQRUNSTS_GLOB, WQ_id, 1, val);
    stq_le_p(&state->regs_rw[GLOB_CONF][DCE_REG_FUNC_WQ_RUN_STS], WQRUNSTS);

}

static void process_wqs(DCEState * state) {

    assert(state);
    uint64_t base = 0, head = 0, head_mod = 0, tail = 0;
    dma_addr_t WQITBA = ldq_le_p(&state->regs_rw[0][DCE_REG_WQITBA]);
    uint64_t WQENABLE = ldq_le_p(&state->regs_rw[0][DCE_REG_WQENABLE]);
    // printf("WQITBA: 0x%lx\n", WQITBA);
    WQITE * WQITEs = calloc(1, 0x1000);
    /* FIXME: use WQMCC.TRANSCTL for this access */
    pci_dma_read(&state->dev, WQITBA, WQITEs, 0x1000);

    /* Iterate thru all WQs and see if there is any work to do */
    for (int i = 0; i < NUM_WQ; i ++) {
        /* skip the WQ if it is not enabled */
        if (!(WQENABLE & BIT(i)))
            continue;

        /* WQCR begins at page 1 */
        uint32_t WQCR = ldl_le_p(&state->regs_rw[i+1][DCE_REG_WQCR]);

        if (FIELD_EX32(WQCR, DCE_WQCR, STATUS) == READY_TO_RUN) {
            // printf("DSCBA: 0x%lx, DSCSZ: %d, DSCPTA: 0x%lx\n",
            //     WQITEs[i].DSCBA, WQITEs[i].DSCSZ, WQITEs[i].DSCPTA);
            base = WQITEs[i].DSCBA;
            //TODO: Error if incorrectly aligned: DSCBA, DSCPTA cat2?

            /* get the head and tail pointer information */
            // printf("WQITEs[i].TRANSCTL: %d\n", WQITEs[i].TRANSCTL);
            MemTxAttrs attrs =
                initialize_pasid_attrs_transctl(state, WQITEs[i].TRANSCTL);
            pci_dma_rw(&state->dev,
                WQITEs[i].DSCPTA + RING_HEADER_HEAD_OFFSET,
                &head, 8, DMA_DIRECTION_TO_DEVICE, attrs);
            pci_dma_rw(&state->dev,
                WQITEs[i].DSCPTA + RING_HEADER_TAIL_OFFSET,
                &tail, 8, DMA_DIRECTION_TO_DEVICE, attrs);
            /* keep processing until we catch up */
            // Generate mask to get buf pos from index
            // Should be 6+DSCSZ bits
            // 4096B pqges, 64B per descriptor, 6 bit for page indexing
            // DSCSZ bits for page indexing inside the queue
            const uint64_t head_mask = (1<<(6+WQITEs[i].DSCSZ))-1;
            while (head < tail) {
                head_mod = head & head_mask;
                dma_addr_t descriptor_addr = base +
                    (head_mod * sizeof(DCEDescriptor));
                // printf("processing descriptor 0x%lx\n", descriptor_addr);
                /* Actually process the descriptor */
                printf("Job queue %d: Starting job at index %"PRIx64"\n", i, head_mod);
                finish_descriptor(state, i, descriptor_addr, WQITEs[i].TRANSCTL);
                head++;
                //TODO: Update head on job completion?
            }
            pci_dma_rw(&state->dev, WQITEs[i].DSCPTA,
                &head, 8, DMA_DIRECTION_FROM_DEVICE, attrs);
        }
        /* set the WQ back to idle if we finished the job */
        if (head == tail) {
            qemu_mutex_lock(&state->core_lock);
            set_ready_to_run_all_places(state, i, IDLE);
            qemu_mutex_unlock(&state->core_lock);
        }
    }
    free(WQITEs);
}

static void process_notify(DCEState * state, unsigned * exec) {

    assert(state);
    // printf("in %s\n", __func__);
    for (int i = 0; i < NUM_WQ; i ++) {
        qemu_mutex_lock(&state->core_lock);
        uint32_t WQCR = ldl_le_p(&state->regs_rw[i+1][DCE_REG_WQCR]);
        // printf("WQCR is 0x%x\n", WQCR);
        if (FIELD_EX32(WQCR, DCE_WQCR, NOTIFY) == 1) {
            /* clear notify, and set status to ready to run */
            WQCR = FIELD_DP32(WQCR, DCE_WQCR, NOTIFY, 0);
            /* FXIME: does WQENABLE affect this ? */
            set_ready_to_run_all_places(state, i, READY_TO_RUN);
            *exec |= BIT(DCE_EXEC_READY_TO_RUN);
        }
        if (FIELD_EX32(WQCR, DCE_WQCR, ABORT) == 1) {
            /* TODO */
        }
        qemu_mutex_unlock(&state->core_lock);
    }
}

static void reset_func_weights(DCEState * state) {
    state->arb_weight_sum = 0;
    uint8_t * temp;
    for (int i = 0; i < 8; i++) {
        temp = (uint8_t * )&state->arb_weight;
        state->arb_weight_sum += *temp;
    }
    qemu_mutex_lock(&state->core_lock);
    stq_le_p(&state->regs_rw[GLOB_CONF][DCE_REG_ARB_WGT], state->arb_weight);
    qemu_mutex_unlock(&state->core_lock);
}

static void *dce_core_proc(void* arg)
{
    DCEState * pfstate = arg;
    DCEState * state;

    unsigned exec = 0;
    unsigned mask = 0;

    uint8_t credit = 0;

    while(1) {
        // printf("exec is 0x%x\n", exec);
        mask = (mask ? mask : BIT(DCE_EXEC_LAST)) >> 1;
        if (pfstate->arb_weight_sum == 0)
            reset_func_weights(pfstate);
        for(int i = 0; i <= DCE_TOTAL_VFS; i++) {
            qemu_mutex_lock(&pfstate->core_lock);
            credit = pfstate->regs_rw[GLOB_CONF][DCE_REG_ARB_WGT + i];
            /* deduct from the credit */
            if (credit > 0) {
                pfstate->regs_rw[GLOB_CONF][DCE_REG_ARB_WGT + i]--;
                pfstate->arb_weight_sum--;
            }
            qemu_mutex_unlock(&pfstate->core_lock);
            /* skip the function if credit has already been depleted */
            // printf("Credit is %d for VF %d\n", credit, i);
            if (credit == 0) continue;

            state = pfstate->all_states[i];
            if (!state) continue;
            switch (exec & mask) {
                /* FIXME make these bits per function? */
                case BIT(DCE_EXEC_NOTIFY):
                    process_notify(state, &exec);
                    break;
                case BIT(DCE_EXEC_READY_TO_RUN):
                    process_wqs(state);
                    break;
                case BIT(DCE_EXEC_RESET_ARB_WEIGHT) :
                    /* FIXME: this is a global operation */
                    reset_func_weights(pfstate);
                    exec &= ~BIT(DCE_EXEC_RESET_ARB_WEIGHT);
                    break;
            }
        }
        exec &= ~mask;
        exec |= qatomic_xchg(&pfstate->core_exec, 0);
        if (!exec) {
            qemu_mutex_lock(&pfstate->core_lock);
            qemu_cond_wait(&pfstate->core_cond, &pfstate->core_lock);
            qemu_mutex_unlock(&pfstate->core_lock);
        }
        // printf("woken up!\n");
    }
    return NULL;
}

#include "qemu/units.h"
static void dce_realize(PCIDevice *dev, Error **errp)
{
    // printf("in %s\n", __func__);
    DCEState *state = DO_UPCAST(DCEState, dev, dev);

    dev->cap_present |= QEMU_PCI_CAP_EXPRESS;

    pci_config_set_interrupt_pin(dev->config, 1);

    memory_region_init_io(&state->mmio, OBJECT(state),
        &dce_mmio_ops, state, "dce-mmio", 512 * KiB);
    // printf("dce mmio: 0x%lx \n",state->mmio.addr);
    pci_register_bar(dev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &state->mmio);

    /* Mark all registers read-only */
    memset(state->regs_ro, 0xff, sizeof(state->regs_ro));
    memset(state->regs_rw, 0x00, sizeof(state->regs_rw));
    /* mark the WQMCC page as RW */
    memset(state->regs_ro, 0x00, DCE_PAGE_SIZE);

    /* WQCR pages, mark NOTIFY / ABORT as RW */
    for (int i = 1; i <= NUM_WQ; i++) {
        stw_le_p(&state->regs_ro[i][DCE_REG_WQCR], 0);
    }

    int ret = pcie_endpoint_cap_init(dev, 0xa0);
    if (ret < 0) {
        printf("caps INIT FAILED\n");
    }
    ret = msi_init(&state->dev, 0, 1, true, false, errp);
    if (ret != 0) {
        printf("MSI INIT FAILED\n");
    }
    pcie_ari_init(dev, PCI_CONFIG_SPACE_SIZE, 1);

    /* PASID capability */
    pcie_add_capability(dev, 0x1b, 1, 0x200, 8);
    pci_set_long(dev->config + 0x200 + 4, 0x00001400);
    pci_set_long(dev->wmask + 0x200 + 4,  0xfff0ffff);


    pcie_sriov_pf_init(dev, 0x160, TYPE_PCI_DCEVF_DEVICE,
                       PCI_DEVICE_ID_RIVOS_DCE_VF, DCE_TOTAL_VFS, DCE_TOTAL_VFS,
                       DCE_VF_OFFSET, DCE_VF_STRIDE);

    /* 3.5 MiB of VFBAR */
    pcie_sriov_pf_init_vf_bar(dev, 0, PCI_BASE_ADDRESS_MEM_TYPE_64 ,
                              0x380000);

    state->pfstate = state;
    state->isVF = false;

    state->all_states[DCE_TOTAL_VFS] = state;
    /* start the core thread */
    qemu_cond_init(&state->core_cond);
    qemu_mutex_init(&state->core_lock);

    /* config intialization */
    /* initialize arb weight */
    state->arb_weight = DCE_DEFAULT_ARB_WEIGHT;
    reset_func_weights(state);
    /* initialize global function WQ processing control */
    state->regs_rw[GLOB_CONF][DCE_REG_FUNC_WQ_PROCESSING_CTL] = 0xff;

    qemu_thread_create(&state->core_proc, "dce-core",
        dce_core_proc, state, QEMU_THREAD_JOINABLE);
}

static void dcevf_realize(PCIDevice *dev, Error **errp)
{
    // printf("in %s\n", __func__);
    uint16_t vfnum = pcie_sriov_vf_number(dev);
    // printf("in %s, setting up VF number %d\n", __func__, vfnum);
    DCEState *vfstate = DO_UPCAST(DCEState, dev, dev);

    PCIDevice * pfdev = pcie_sriov_get_pf(dev);
    DCEState *pfstate = DO_UPCAST(DCEState, dev, pfdev);

    pfstate->all_states[vfnum] = vfstate;

    vfstate->pfstate = pfstate;
    vfstate->isVF = true;
    vfstate->vfnum = vfnum;

    MemoryRegion *mr = &vfstate->mmio;

    memory_region_init_io(mr, OBJECT(vfstate), &dce_mmio_ops, vfstate,
            "dcevf-mmio", 512 * KiB);
    pcie_sriov_vf_register_bar(dev, 0, mr);

    int ret = pcie_endpoint_cap_init(dev, 0xa0);
    if (ret < 0) {
        printf("VF error: cap\n");
    }
    ret = msi_init(&vfstate->dev, 0, 1, true, false, errp);
    if (ret != 0) {
        printf("MSI INIT FAILED\n");
    }
    pcie_ari_init(dev, 0x100, 1);

    qemu_cond_init(&vfstate->core_cond);
    qemu_mutex_init(&vfstate->core_lock);
}

static void dcevf_instance_init(Object *obj) {}
static void dce_instance_init(Object *obj) {}

static void dce_uninit(PCIDevice *dev) {}
static void dcevf_uninit(PCIDevice *dev) {}

static Property dce_properties[] = {
    DEFINE_PROP_BOOL("pasid", DCEState, enable_pasid, TRUE),
    DEFINE_PROP_END_OF_LIST(),
};

static void dcevf_class_init(ObjectClass *class, void *data)
{
    PCIDeviceClass *k = PCI_DEVICE_CLASS(class);
    k->realize      = dcevf_realize;
    k->exit         = dcevf_uninit;
    k->vendor_id    = PCI_VENDOR_ID_RIVOS;
    k->device_id    = PCI_DEVICE_ID_RIVOS_DCE;
    k->class_id     = PCI_CLASS_OTHERS;
//     k->config_read  = dce_config_read;
//     k->config_write = dce_config_write;

    DeviceClass *dc = DEVICE_CLASS(class);
    device_class_set_props(dc, dce_properties);
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    dc->desc = "DCE Virtual Function";
}

static void dce_class_init(ObjectClass *class, void *data)
{
    PCIDeviceClass *k = PCI_DEVICE_CLASS(class);
    k->realize      = dce_realize;
    k->exit         = dce_uninit;
    k->vendor_id    = PCI_VENDOR_ID_RIVOS;
    k->device_id    = PCI_DEVICE_ID_RIVOS_DCE;
    k->class_id     = PCI_CLASS_OTHERS;
//     k->config_read  = dce_config_read;
//     k->config_write = dce_config_write;

    DeviceClass *dc = DEVICE_CLASS(class);
    device_class_set_props(dc, dce_properties);
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    dc->desc = "DCE Physical Function";
}

static const TypeInfo dce_info = {
    .name          = TYPE_PCI_DCE_DEVICE,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(DCEState),
    .instance_init = dce_instance_init,
    .class_init    = dce_class_init,
    .interfaces    = (InterfaceInfo[]) {
        { INTERFACE_PCIE_DEVICE },
        { }
    }
};

static const TypeInfo dcevf_info = {
    .name          = TYPE_PCI_DCEVF_DEVICE,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(DCEState),
    .instance_init = dcevf_instance_init,
    .class_init    = dcevf_class_init,
    .interfaces    = (InterfaceInfo[]) {
        { INTERFACE_PCIE_DEVICE },
        { }
    }
};

static void dce_register(void)
{
    type_register_static(&dce_info);
    type_register_static(&dcevf_info);
}

type_init(dce_register);
