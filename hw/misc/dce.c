#include "qemu/osdep.h"
#include "hw/qdev-properties.h"
#include "migration/vmstate.h"
#include "qom/object.h"
#include "hw/pci/pci.h"
#include "hw/hw.h"
#include "hw/misc/dce.h"
#include "hw/pci/msi.h"
#include <signal.h>

#define reg_addr(reg) (A_ ## reg)

typedef struct DCEState {
    PCIDevice dev;
    MemoryRegion mmio;

    bool enable;

    uint64_t descriptor_ring_ctrl_base;
    uint64_t descriptor_ring_ctrl_limit;
    uint64_t descriptor_ring_ctrl_head;
    uint64_t descriptor_ring_ctrl_tail;

    InterruptSourceInfo interrupt_source_infos[DCE_INTERRUPT_MAX];
    uint64_t interrupt_mask;
    uint64_t interrupt_status;
} DCEState;

static void raise_interrupt(DCEState *state, DCEInterruptSource interrupt_source)
{
    if (state->interrupt_source_infos[interrupt_source].enable &&
        (state->interrupt_mask >> interrupt_source) & 1) {

        state->interrupt_status |= 1 << interrupt_source;
        msi_notify(&state->dev, state->interrupt_source_infos[interrupt_source].vector_index);
    }
}

static void reset(DCEState *state)
{
    // TODO: fill this out later when it's clear what happens here
}

static bool aligned(hwaddr addr, unsigned size)
{
    return addr % size == 0;
}

static bool interrupt_on_completion(struct DCEDescriptor *descriptor)
{
    return descriptor->ctrl & 1;
}

static uint64_t populate_completion(uint8_t status, uint8_t spec, uint64_t data) {
    uint64_t completion = 0;
    completion = FIELD_DP64(completion, DCE_COMPLETION, DATA, data);
    completion = FIELD_DP64(completion, DCE_COMPLETION, SPEC, spec);
    completion = FIELD_DP64(completion, DCE_COMPLETION, STATUS, status);
    completion = FIELD_DP64(completion, DCE_COMPLETION, VALID, 1);
    return completion;
}

static void dce_memcpy(DCEState *state, struct DCEDescriptor *descriptor)
{
    int offset;
    uint64_t completion = 0;
    int err = 0;
    int status = STATUS_PASS;
    printf("Memcpy %lu bytes from 0x%lx -> 0x%lx\n",
            descriptor->operand1, descriptor->source, descriptor->dest);
    for (offset = 0; offset < descriptor->operand1; offset++)
    {
        uint8_t temp;
        err |= pci_dma_read (&state->dev, descriptor->source + offset, &temp, 1);
        err |= pci_dma_write(&state->dev, descriptor->dest   + offset, &temp, 1);
        if (err) {
            status = STATUS_FAIL;
            break;
        }
    }
    completion = populate_completion(status, 0, offset);
    pci_dma_write(&state->dev, descriptor->completion, &completion, 8);
}

static void dce_memset(DCEState *state, struct DCEDescriptor *descriptor)
{
    printf("Inside %s\n", __func__);
    for (int offset = 0; offset < descriptor->operand1; offset++)
    {
        uint8_t temp;
        pci_dma_read (&state->dev, descriptor->source + (offset % 16), &temp, 1);
        pci_dma_write(&state->dev, descriptor->dest   + offset,        &temp, 1);
    }
}

static void dce_memcmp(DCEState *state, struct DCEDescriptor *descriptor)
{
    // TODO: implement the bitmask version after the spec is settled
    // bool generate_bitmask = descriptor->operand0 & 1;
    bool generate_bitmask = false;
    uint64_t completion = 0;
    hwaddr source1 = descriptor->source;
    hwaddr source2 = descriptor->operand2;

    bool     diff_found = false;
    uint32_t first_diff_index = 0;


    for (int offset = 0; offset < descriptor->operand1; offset++)
    {
        uint8_t byte1, byte2;
        pci_dma_read(&state->dev, source1 + offset, &byte1, 1);
        pci_dma_read(&state->dev, source2 + offset, &byte2, 1);
        // printf("Compareing '%c' and '%c'\n", (char)byte1, (char)byte2);
        uint8_t result = byte1 ^ byte2;

        if (result != 0) {
            diff_found = true;
            if (!generate_bitmask) {
                first_diff_index = offset;
                break;
            }
        }
        // if (generate_bitmask) {
        //     pci_dma_write(&state->dev, descriptor->dest + offset, &result, 1);
        // }
    }

    if (!generate_bitmask) {
        uint64_t result = diff_found ? 1 : 0;
        completion = populate_completion(STATUS_PASS, 0, (1 << first_diff_index));
        pci_dma_write(&state->dev, descriptor->completion, &completion, 8);
        pci_dma_write(&state->dev, descriptor->dest, &result, 8);
    }
}

static void finish_descriptor(DCEState *state, hwaddr descriptor_address)
{
    struct DCEDescriptor descriptor;
    MemTxResult ret = pci_dma_read(&state->dev, descriptor_address, &descriptor, 64);
    if (ret) printf("ERROR: %x\n", ret);
    printf("Processing descriptor with opcode %d\n", descriptor.opcode);

    switch (descriptor.opcode) {
        case DCE_OPCODE_MEMCPY: dce_memcpy(state, &descriptor); break;
        case DCE_OPCODE_MEMSET: dce_memset(state, &descriptor); break;
        case DCE_OPCODE_MEMCMP: dce_memcmp(state, &descriptor); break;
    }

    if (interrupt_on_completion(&descriptor)) {
        raise_interrupt(state, DCE_INTERRUPT_DESCRIPTOR_COMPLETION);
    }
}

static void finish_unfinished_descriptors(DCEState *state)
{
    hwaddr current_descriptor_address = state->descriptor_ring_ctrl_head;
    printf("Current head: 0x%lx, Current tail: 0x%lx\n", state->descriptor_ring_ctrl_head,
                                                         state->descriptor_ring_ctrl_tail);
    while (current_descriptor_address != state->descriptor_ring_ctrl_tail) {
        printf("In loop...current descriptor address: 0x%lx\n", current_descriptor_address);
        finish_descriptor(state, current_descriptor_address);
        current_descriptor_address += sizeof(DCEDescriptor);
        if (current_descriptor_address == state->descriptor_ring_ctrl_limit + sizeof(DCEDescriptor)) current_descriptor_address = state->descriptor_ring_ctrl_base;
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
    state->descriptor_ring_ctrl_tail &= ~0x7;

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

static void dce_instance_init(Object *obj)
{

}

static void dce_uninit(PCIDevice *dev)
{

}

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

    if (msi_init(dev, 0, 1, true, false, errp)) {
        return;
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