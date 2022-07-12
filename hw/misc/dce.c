#include "qemu/osdep.h"
#include "hw/qdev-properties.h"
#include "migration/vmstate.h"
#include "qom/object.h"
#include "hw/pci/pci.h"
#include "hw/hw.h"
#include "hw/misc/dce.h"
#include "hw/pci/msi.h"
#include <signal.h>

#include "lz4.h"
#include "snappy-c.h"
#include "zlib.h"
#include "zstd.h"

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define reg_addr(reg) (A_ ## reg)
#define DCE_AES_KEYLEN    32

typedef struct DCEState
{
    PCIDevice dev;
    MemoryRegion mmio;

    bool enable;

    uint32_t irq_status;

    uint64_t descriptor_ring_ctrl_base;
    uint64_t descriptor_ring_ctrl_limit;
    uint64_t descriptor_ring_ctrl_head;
    uint64_t descriptor_ring_ctrl_tail;

    InterruptSourceInfo interrupt_source_infos[DCE_INTERRUPT_MAX];
    uint64_t interrupt_mask;
    uint64_t interrupt_status;

    /* Storage for 8 32B keys */
	unsigned char keys[8][32];
} DCEState;

static bool dce_msi_enabled(DCEState *state)
{
    return msi_enabled(&state->dev);
}

static void dce_raise_interrupt(DCEState *state, DCEInterruptSource val)
{
    printf("Issuing interrupt!\n");
    state->irq_status |= val;
    if (state->irq_status) {
        if (dce_msi_enabled(state)) {
            msi_notify(&state->dev, 0);
        }
    }
}

// static void dce_lower_interrupt(DCEState *state, DCEInterruptSource val)
// {
//     state->irq_status &= ~val;
// }

static void reset(DCEState *state)
{
    // TODO: fill this out later when it's clear what happens here
}

static bool aligned(hwaddr addr, unsigned size)
{
    return addr % size == 0;
}

static inline bool interrupt_on_completion(DCEState *state,
                                           struct DCEDescriptor *descriptor)
{
    printf("ctrl is 0x%x\n", descriptor->ctrl);
    printf("MSI enabled? %d\n", dce_msi_enabled(state));
    return ((descriptor->ctrl & 1) && dce_msi_enabled(state));
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
                              int err, uint8_t spec, uint64_t data)
{
    int status = STATUS_PASS;
    uint64_t completion = 0;

    if (err) {
        printf("ERROR: operation has failed!\n");
        status = STATUS_FAIL;
    }
    completion = populate_completion(status, spec, data);
    pci_dma_write(&state->dev, descriptor->completion, &completion, 8);

    if (interrupt_on_completion(state, descriptor))
        dce_raise_interrupt(state, DCE_INTERRUPT_DESCRIPTOR_COMPLETION);
}

/* Data processing functions */
static void get_next_ptr_and_size(PCIDevice * dev, uint64_t * entry,
                                  uint64_t * curr_ptr, uint64_t * curr_size,
                                  bool is_list, size_t size)
{
    int err = 0;
    uint64_t next_level_entry = *entry;
    if (is_list) {
        do {
            *entry = next_level_entry;
            err |= pci_dma_read(dev, *entry, curr_ptr, 8);
            err |= pci_dma_read(dev, (*entry) + 8, curr_size, 8);
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
        printf("Read buffer: 0x%lx\n",  *curr_ptr);
        printf("Read size: 0x%lx\n", *curr_size);
    }
}

static int local_buffer_tranfer(DCEState *state, uint8_t * local, hwaddr src,
                                size_t size,bool is_list, int dir)
{
    int err = 0, bytes_finished = 0;
    uint64_t curr_ptr;
    uint64_t curr_size = 0;
    while(bytes_finished < size) {
        get_next_ptr_and_size(&state->dev, &src, &curr_ptr,
                              &curr_size, is_list, size);
        if (dir == TO_LOCAL)
            err |= pci_dma_read(&state->dev, curr_ptr,
                                &local[bytes_finished], curr_size);
        else
            err |= pci_dma_write(&state->dev, curr_ptr,
                                 &local[bytes_finished], curr_size);
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

static void dce_memcpy(DCEState *state, struct DCEDescriptor *descriptor)
{
    uint64_t size = descriptor->operand1;
    uint8_t * local_buffer = malloc(size);

    hwaddr dest = descriptor->dest;
    hwaddr src = descriptor->source;
    int err = 0;

    bool dest_is_list = (descriptor->ctrl & DEST_IS_LIST) ? true : false;
    bool src_is_list = (descriptor->ctrl & SRC_IS_LIST) ? true : false;

    /* copy to local buffer */
    err |= local_buffer_tranfer(state, local_buffer, src,
                                size, src_is_list, TO_LOCAL);
    /* copy to dest from local buffer */
    err |= local_buffer_tranfer(state, local_buffer, dest,
                                size, dest_is_list, FROM_LOCAL);

    complete_workload(state, descriptor, err, 0, size);
    free(local_buffer);
}

static void dce_memset(DCEState *state, struct DCEDescriptor *descriptor)
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

    err |= local_buffer_tranfer(state, local_buffer, dest, size,
                                is_list, FROM_LOCAL);
    complete_workload(state, descriptor, err, 0, size);
    free(local_buffer);
}

static void dce_memcmp(DCEState *state, struct DCEDescriptor *descriptor)
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

    err |= local_buffer_tranfer(state, src_local, src, size,
                                src_is_list, TO_LOCAL);
    err |= local_buffer_tranfer(state, src2_local, src2, size,
                                src2_is_list, TO_LOCAL);

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
        err |= local_buffer_tranfer(state, dest_local, dest,
                                    size, dest_is_list, FROM_LOCAL);
    else
        pci_dma_write(&state->dev, descriptor->dest, &diff_found, 8);

    first_diff_index = diff_found ? (1 << first_diff_index) : 0;
    complete_workload(state, descriptor, err, 0, first_diff_index);

    free(src_local);
    free(src2_local);
    free(dest_local);
}

static int encrypt_aes_xts_256(const uint8_t * plain_text, uint32_t plain_text_len,
                       const uint8_t * cipher_key, const uint8_t * iv,
                       uint8_t * cipher_text)
{
    if ((plain_text == NULL) ||
        (cipher_text == NULL) ||
        (cipher_key == NULL) ||
        (plain_text_len == 0)) {
        return -1;
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL) {
        return -2;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_xts(), NULL, cipher_key, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -3;
    }
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -4;
    }

    int encrypted_length = 0;

    if (EVP_EncryptUpdate(ctx, cipher_text, &encrypted_length,
                          plain_text, plain_text_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -5;
    }

    if (encrypted_length != plain_text_len) {
        int final_length = 0;
        if (EVP_EncryptFinal_ex(ctx, cipher_text + encrypted_length, &final_length) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return -6;
        }
        encrypted_length += final_length;
    }

    EVP_CIPHER_CTX_free(ctx);
    if (encrypted_length != plain_text_len) {
        return -7;
    }
    return encrypted_length;
}

static int decrypt_aes_xts_256(const uint8_t * cipher_text, uint32_t cipher_text_len,
                        const uint8_t * cipher_key, const uint8_t * iv,
                        uint8_t * plain_text)
{
    if ((plain_text == NULL) ||
        (cipher_text == NULL) ||
        (cipher_key == NULL) ||
        (cipher_text_len == 0)) {
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL) {
        return -2;
    }
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_xts(), NULL, cipher_key, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -3;
    }
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -4;
    }

    int decrypted_length = 0;

    if (EVP_DecryptUpdate(ctx, plain_text, &decrypted_length, cipher_text, cipher_text_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -5;
    }

    if (decrypted_length != cipher_text_len) {
        int final_length = 0;
        if (EVP_EncryptFinal_ex(ctx, plain_text + decrypted_length, &final_length) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return -6;
        }
        decrypted_length += final_length;
    }

    EVP_CIPHER_CTX_free(ctx);

    if (decrypted_length != cipher_text_len) {
        return -7;
    }
    return decrypted_length;
}

static int dce_crypto(DCEState *state,
                       struct DCEDescriptor *descriptor,
                       unsigned char * src, unsigned char * dest,
                       uint64_t size, int is_encrypt)
{

    /* TODO sanity check the size / alignment */
    printf("In %s\n", __func__);
    uint8_t iv[16], key[64];
    int err = 0, ret = 0;

    /*
     * |  Byte 3  |   Byte 2   |   Byte 1  |  Byte 0 |
     * | HASH KID | TWEAKIV ID | TWEAK KID | SEC KID |
     */
    uint8_t * key_ids = (uint8_t *)&descriptor->operand3;
    uint8_t sec_kid = key_ids[0];
    uint8_t tweak_kid = key_ids[1];
    uint8_t iv_kid = key_ids[2];

    /* setup the encryption keys*/
    memcpy(key, state->keys[sec_kid], 32);
    memcpy(key + 32, state->keys[tweak_kid], 32);

    /* setting up IV */
    memcpy(iv, state->keys[iv_kid], 16);

    if (is_encrypt == ENCRYPT) {
        ret = encrypt_aes_xts_256(src, size, key, iv, dest);
        if (ret < 0) {
            printf("ERROR:Encrypt failed!\n");
            return -1;
        }
    } else {
        ret = decrypt_aes_xts_256(src, size, key, iv, dest);
        if (ret < 0) {
            printf("ERROR:Decrypt failed!\n");
            return -1;
        }
    }
    return err;
}

static int dce_compress_decompress(struct DCEDescriptor *descriptor,
                                   const char * src, char * dst,
                                   size_t src_size, size_t * dst_size, int dir)
{
    int err = 0;
    /* bit 1-3 in opernad 0 specify the compression format */
    int comp_format = (descriptor->operand0 >> 1) & 0x7;
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
    if(err) printf("ERROR: %d\n", err);
    return err;
}

static void dce_data_process(DCEState *state, struct DCEDescriptor *descriptor)
{
    uint64_t src_size = descriptor->operand1;
    uint64_t dest_size;
    size_t post_process_size, err = 0;
    /* create local buffers used for LZ4 */
    char * src_local = malloc(src_size);
    char * dest_local;
    char * intermediate;

    hwaddr dest = descriptor->dest;
    hwaddr src = descriptor->source;

    bool dest_is_list = (descriptor->ctrl & DEST_IS_LIST) ? true : false;
    bool src_is_list = (descriptor->ctrl & SRC_IS_LIST) ? true : false;

    if (descriptor->opcode == DCE_OPCODE_ENCRYPT ||
        descriptor->opcode == DCE_OPCODE_DECRYPT) {
        /* crypto, dest size == src size */
        dest_size = src_size;
    }
    else {
        /* Compression operations, dest has its own size */
        dest_size = descriptor->operand2;
    }
    dest_local = calloc(dest_size, 1);
    post_process_size = dest_size;

    /* copy to local buffer */
    local_buffer_tranfer(state, (uint8_t *)src_local, src, src_size,
                         src_is_list, TO_LOCAL);

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
            /* TODO: other algorithm */
            err |= dce_crypto(state, descriptor, (uint8_t *)src_local,
                       (uint8_t *)dest_local, src_size, ENCRYPT);
            if (!err) post_process_size = src_size;
            printf("Encrypted %ld bytes\n", post_process_size);
            break;
        case DCE_OPCODE_DECRYPT:

            /* TODO: other algorithm */
            err |= dce_crypto(state, descriptor, (uint8_t *)src_local,
                       (uint8_t *)dest_local, src_size, DECRYPT);
            if (!err) post_process_size = src_size;
            printf("Decrypted %ld bytes\n", post_process_size);
            break;
        case DCE_OPCODE_COMPRESS_ENCRYPT:
            intermediate = calloc(dest_size, 1);
            err |= dce_compress_decompress(descriptor, src_local, intermediate,
                                           src_size, &post_process_size,
                                           COMPRESS);
            printf("Compressed - %ld bytes\n", post_process_size);
            err |= dce_crypto(state, descriptor, (uint8_t *)intermediate,
                       (uint8_t *)dest_local, post_process_size, ENCRYPT);
            free(intermediate);
            break;
        case DCE_OPCODE_DECRYPT_DECOMPRESS:
            intermediate = calloc(src_size, 1);
            err |= dce_crypto(state, descriptor, (uint8_t *)src_local,
                       (uint8_t *)intermediate, src_size, DECRYPT);
            err |= dce_compress_decompress(descriptor, intermediate, dest_local,
                                           src_size, &post_process_size,
                                           DECOMPRESS);
            printf("Decompressed - %ld bytes\n", post_process_size);
            free(intermediate);
            break;
        default:
            break;
    }
    err |= (post_process_size == 0);
    if (err) goto cleanup;
    /* copy back the results */
    local_buffer_tranfer(state, (uint8_t *)dest_local, dest, dest_size,
                         dest_is_list, FROM_LOCAL);

cleanup:
    complete_workload(state, descriptor, err, 0, post_process_size);
    free(src_local);
    free(dest_local);
}

static void dce_load_key(DCEState *state, struct DCEDescriptor *descriptor)
{
    printf("In %s\n", __func__);
    unsigned char * key = state->keys[descriptor->dest];
    uint64_t * src = (uint64_t *)descriptor->source;
    pci_dma_read(&state->dev, (dma_addr_t)src, key, DCE_AES_KEYLEN);
    complete_workload(state, descriptor, 0, 0, DCE_AES_KEYLEN);
}

static void dce_clear_key(DCEState *state, struct DCEDescriptor *descriptor)
{
    printf("In %s\n", __func__);
    unsigned char * key = state->keys[descriptor->dest];
    memset(key, 0, DCE_AES_KEYLEN);
    complete_workload(state, descriptor, 0, 0, DCE_AES_KEYLEN);
}

static void finish_descriptor(DCEState *state, hwaddr descriptor_address)
{
    struct DCEDescriptor descriptor;
    MemTxResult ret = pci_dma_read(&state->dev,
                                   descriptor_address, &descriptor, 64);
    if (ret) printf("ERROR: %x\n", ret);
    printf("Processing descriptor with opcode %d\n", descriptor.opcode);

    switch (descriptor.opcode) {
        case DCE_OPCODE_MEMCPY:     dce_memcpy(state, &descriptor); break;
        case DCE_OPCODE_MEMSET:     dce_memset(state, &descriptor); break;
        case DCE_OPCODE_MEMCMP:     dce_memcmp(state, &descriptor); break;
        case DCE_OPCODE_COMPRESS:
        case DCE_OPCODE_DECOMPRESS:
        case DCE_OPCODE_ENCRYPT:
        case DCE_OPCODE_DECRYPT:
        case DCE_OPCODE_DECRYPT_DECOMPRESS:
        case DCE_OPCODE_COMPRESS_ENCRYPT:
            dce_data_process(state, &descriptor); break;
        case DCE_OPCODE_LOAD_KEY:   dce_load_key(state, &descriptor); break;
        case DCE_OPCODE_CLEAR_KEY:  dce_clear_key(state, &descriptor); break;
    }
}

static void finish_unfinished_descriptors(DCEState *state)
{
    hwaddr current_descriptor_address = state->descriptor_ring_ctrl_head;
    printf("Current head: 0x%lx, Current tail: 0x%lx\n",
            state->descriptor_ring_ctrl_head, state->descriptor_ring_ctrl_tail);
    while (current_descriptor_address != state->descriptor_ring_ctrl_tail) {
        printf("In loop...current descriptor address: 0x%lx\n",
                current_descriptor_address);
        finish_descriptor(state, current_descriptor_address);
        current_descriptor_address += sizeof(DCEDescriptor);
        if (current_descriptor_address ==
            state->descriptor_ring_ctrl_limit + sizeof(DCEDescriptor))
            current_descriptor_address = state->descriptor_ring_ctrl_base;
    }
    state->descriptor_ring_ctrl_head = current_descriptor_address;
}

static uint64_t read_dce_ctrl(DCEState *state, int offset, unsigned size)
{
    uint64_t result = 0;

    for (int i = 0; i < size; i++) {
        switch (offset + i) {
            case 0: result = deposit64(result, i * 8, 1, state->enable);
        }
    }

    return result;
}

static uint64_t read_dce_status(DCEState *state, int offset, unsigned size)
{
    uint64_t result = 0;

    for (int i = 0; i < size; i++) {
        switch (offset + i) {
            case 0: result = deposit64(result, i * 8, 1, state->enable);
        }
    }

    return result;
}


static void write_dce_ctrl(DCEState *state, int offset, uint64_t val, unsigned size)
{
    for (int i = 0; i < size; i++) {
        switch (offset + i) {
            case 0:
                state->enable = extract64(val, i * 8, 1);

                if (state->enable) {
                    state->descriptor_ring_ctrl_tail = state->descriptor_ring_ctrl_base;
                    state->descriptor_ring_ctrl_head = state->descriptor_ring_ctrl_base;
                }
                if (extract64(val, 1, 1)) reset(state);
                break;
        }
    }
}

static uint64_t read_descriptor_ring_ctrl_base(DCEState *state, int offset, unsigned size)
{
    return extract64(state->descriptor_ring_ctrl_base, offset * 8, size * 8);
}

static void write_descriptor_ring_ctrl_base(DCEState *state, int offset, uint64_t val, unsigned size)
{
    state->descriptor_ring_ctrl_base = deposit64(state->descriptor_ring_ctrl_base, offset * 8, size * 8, val);
    // state->descriptor_ring_ctrl_base &= ~0xFFF;
}

static uint64_t read_descriptor_ring_ctrl_limit(DCEState *state, int offset, unsigned size)
{
    return extract64(state->descriptor_ring_ctrl_limit, offset * 8, size * 8);
}

static void write_descriptor_ring_ctrl_limit(DCEState *state, int offset, uint64_t val, unsigned size)
{
    state->descriptor_ring_ctrl_limit = deposit64(state->descriptor_ring_ctrl_limit, offset * 8, size * 8, val);
    // state->descriptor_ring_ctrl_limit &= ~0xFFF;
}

static uint64_t read_descriptor_ring_ctrl_head(DCEState *state, int offset, unsigned size)
{
    return 0; // TODO: not allowed
}

static void write_descriptor_ring_ctrl_head(DCEState *state, int offset, uint64_t val, unsigned size)
{

}

static uint64_t read_descriptor_ring_ctrl_tail(DCEState *state, int offset, unsigned size)
{
    return extract64(state->descriptor_ring_ctrl_tail, offset * 8, size * 8);
}

static void write_descriptor_ring_ctrl_tail(DCEState *state, int offset, uint64_t val, unsigned size)
{
    state->descriptor_ring_ctrl_tail = deposit64(state->descriptor_ring_ctrl_tail, offset * 8, size * 8, val);
    // state->descriptor_ring_ctrl_tail &= ~0x7;

    if (state->descriptor_ring_ctrl_tail != state->descriptor_ring_ctrl_head) {
        finish_unfinished_descriptors(state);
    }
}

static uint64_t read_interrupt_config(DCEState *state, int offset, unsigned size, DCEInterruptSource interrupt_source)
{
    InterruptSourceInfo info = state->interrupt_source_infos[interrupt_source];

    uint64_t result = 0;

    for (int i = 0; i < size; i++) {
        switch (offset + i) {
            case 0: result = deposit64(result, i * 8, 8, extract64(info.vector_index,  0, 8)); break;
            case 1: result = deposit64(result, i * 8, 8, extract64(info.vector_index,  8, 8)); break;
            case 2: result = deposit64(result, i * 8, 8, extract64(info.vector_index, 16, 8)); break;
            case 3: result = deposit64(result, i * 8, 8, extract64(info.vector_index, 24, 8)); break;

            case 7: result = deposit64(result, i * 8, 8, info.enable << 7); break;
        }
    }

    return result;
}

static uint64_t write_interrupt_config(DCEState *state, int offset, uint64_t val, unsigned size, DCEInterruptSource interrupt_source)
{
    InterruptSourceInfo info = state->interrupt_source_infos[interrupt_source];

    uint64_t result = 0;

    for (int i = 0; i < size; i++) {
        switch (offset + i) {
            case 0: info.vector_index = deposit64(info.vector_index,  0, 8, extract64(val, i * 8, 8)); break;
            case 1: info.vector_index = deposit64(info.vector_index,  8, 8, extract64(val, i * 8, 8)); break;
            case 2: info.vector_index = deposit64(info.vector_index, 16, 8, extract64(val, i * 8, 8)); break;
            case 3: info.vector_index = deposit64(info.vector_index, 24, 8, extract64(val, i * 8, 8)); break;

            case 7: info.enable = extract64(val, i * 8 + 7, 1); break;
        }
    }

    return result;
}

static uint64_t read_interrupt_status(DCEState *state, int offset, unsigned size)
{
    return extract64(state->interrupt_status, offset * 8, size * 8);
}

static void write_interrupt_status(DCEState *state, int offset, uint64_t val, unsigned size)
{
    state->interrupt_status = deposit64(state->interrupt_status, offset * 8, size * 8, state->interrupt_status & ~val);
}

static uint64_t read_interrupt_mask(DCEState *state, int offset, unsigned size)
{
    return extract64(state->interrupt_mask, offset * 8, size * 8);
}

static void write_interrupt_mask(DCEState *state, int offset, uint64_t val, unsigned size)
{
    state->interrupt_mask = deposit64(state->interrupt_mask, offset * 8, size * 8, val);
}

#define TYPE_PCI_DCE_DEVICE "dce"
DECLARE_INSTANCE_CHECKER(DCEState, DCE, TYPE_PCI_DCE_DEVICE)

static void dce_instance_init(Object *obj) {}

static void dce_uninit(PCIDevice *dev) {}

static uint64_t dce_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    assert(aligned(addr, size));

    DCEState *state = (DCEState*) opaque;

    uint64_t result = 0;

    hwaddr reg_addr = addr & ~3;
    int    offset   = addr &  3;

    if (reg_addr == A_DCE_CTRL)                                   result = read_dce_ctrl                  (state, offset, size);
    if (reg_addr == A_DCE_STATUS)                                 result = read_dce_status                (state, offset, size);
    if (reg_addr == A_DCE_DESCRIPTOR_RING_CTRL_BASE)              result = read_descriptor_ring_ctrl_base (state, offset, size);
    if (reg_addr == A_DCE_DESCRIPTOR_RING_CTRL_LIMIT)             result = read_descriptor_ring_ctrl_limit(state, offset, size);
    if (reg_addr == A_DCE_DESCRIPTOR_RING_CTRL_HEAD)              result = read_descriptor_ring_ctrl_head (state, offset, size);
    if (reg_addr == A_DCE_DESCRIPTOR_RING_CTRL_TAIL)              result = read_descriptor_ring_ctrl_tail (state, offset, size);
    if (reg_addr == A_DCE_INTERRUPT_CONFIG_DESCRIPTOR_COMPLETION) result = read_interrupt_config          (state, offset, size, DCE_INTERRUPT_DESCRIPTOR_COMPLETION);
    if (reg_addr == A_DCE_INTERRUPT_CONFIG_TIMEOUT)               result = read_interrupt_config          (state, offset, size, DCE_INTERRUPT_TIMEOUT);
    if (reg_addr == A_DCE_INTERRUPT_CONFIG_ERROR_CONDITION)       result = read_interrupt_config          (state, offset, size, DCE_INTERRUPT_ERROR_CONDITION);
    if (reg_addr == A_DCE_INTERRUPT_STATUS)                       result = read_interrupt_status          (state, offset, size);
    if (reg_addr == A_DCE_INTERRUPT_MASK)                         result = read_interrupt_mask            (state, offset, size);


    return result;
}

static void dce_mmio_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    assert(aligned(addr, size));

    DCEState *state = (DCEState*) opaque;

    hwaddr reg_addr = addr & ~3;
    int    offset   = addr &  3;

    if (reg_addr == A_DCE_CTRL)                                   write_dce_ctrl                  (state, offset, val, size);
    if (reg_addr == A_DCE_DESCRIPTOR_RING_CTRL_BASE)              write_descriptor_ring_ctrl_base (state, offset, val ,size);
    if (reg_addr == A_DCE_DESCRIPTOR_RING_CTRL_LIMIT)             write_descriptor_ring_ctrl_limit(state, offset, val, size);
    if (reg_addr == A_DCE_DESCRIPTOR_RING_CTRL_HEAD)              write_descriptor_ring_ctrl_head (state, offset, val, size);
    if (reg_addr == A_DCE_DESCRIPTOR_RING_CTRL_TAIL)              write_descriptor_ring_ctrl_tail (state, offset, val, size);
    if (reg_addr == A_DCE_INTERRUPT_CONFIG_DESCRIPTOR_COMPLETION) write_interrupt_config          (state, offset, val, size, DCE_INTERRUPT_DESCRIPTOR_COMPLETION);
    if (reg_addr == A_DCE_INTERRUPT_CONFIG_TIMEOUT)               write_interrupt_config          (state, offset, val, size, DCE_INTERRUPT_TIMEOUT);
    if (reg_addr == A_DCE_INTERRUPT_CONFIG_ERROR_CONDITION)       write_interrupt_config          (state, offset, val, size, DCE_INTERRUPT_ERROR_CONDITION);
    if (reg_addr == A_DCE_INTERRUPT_STATUS)                       write_interrupt_status          (state, offset, val, size);
    if (reg_addr == A_DCE_INTERRUPT_MASK)                         write_interrupt_mask            (state, offset, val, size);
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

#include "qemu/units.h"
static void dce_realize(PCIDevice *dev, Error **errp)
{

    DCEState *state = DCE(dev);

    dev->cap_present |= QEMU_PCI_CAP_EXPRESS;
    dev->cap_present |= QEMU_PCI_CAP_MSI;

    pci_config_set_interrupt_pin(dev->config, 1);

    int ret = msi_init(&state->dev, 0, 1, true, false, errp);
    if (ret == -ENOTSUP) {
        printf("MSIX INIT FAILED\n");
    }
    else {
        printf("MSIX INIT success\n");
    }

    // TODO: figure out the other qemu capabilities
    // pcie_aer_init(dev, PCI_ERR_VER, )

    memory_region_init_io(&state->mmio, OBJECT(state), &dce_mmio_ops, state, "dce-mmio", 1 * MiB);
    pci_register_bar(dev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &state->mmio);
}

// static uint32_t dce_config_read(PCIDevice *pci_dev, uint32_t addr, int size)
// {
//     return 0;
// }

// static void dce_config_write(PCIDevice *pci_dev, uint32_t addr, uint32_t val, int size)
// {
//     return;
// }

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
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo dce_info = {
    .name          = TYPE_PCI_DCE_DEVICE,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(DCEState),
    .instance_init = dce_instance_init,
    .class_init    = dce_class_init,
    .interfaces    = (InterfaceInfo[]) {
        { INTERFACE_CONVENTIONAL_PCI_DEVICE },
        { }
    }
};

static void dce_register(void)
{
    type_register_static(&dce_info);
}

type_init(dce_register);