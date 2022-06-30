/*
 * Simple MMIO and GPIO relay device
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

#ifndef HW_RELAY_DEVICE
#define HW_RELAY_DEVICE

#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "chardev/char-fe.h"

#define TYPE_RELAY_DEVICE "relay-device"
OBJECT_DECLARE_SIMPLE_TYPE(RelayDevice, RELAY_DEVICE)

typedef struct BusIntercept {
    MemoryRegion *root;
    MemoryRegion  intercept;
} BusIntercept;

typedef struct BusRequester {
    AddressSpace *as;
} BusRequester;

#define RELAY_MAX_RECEIVER      2
#define RELAY_MAX_REQUESTER     2
#define RELAY_MAX_SIGNAL       32

struct RelayDevice {
    SysBusDevice parent_obj;        /* Need to attach to _some_ bus */

    QemuMutex mutex;

    CharBackend recv;
    CharBackend send;

    unsigned num_rcvr;
    BusIntercept intercept[RELAY_MAX_RECEIVER];
    unsigned num_rqst;
    BusRequester requester[RELAY_MAX_REQUESTER];

    /* Signals (gpios) wired across the relay */
    unsigned num_ins;
    unsigned num_outs;
    qemu_irq out[RELAY_MAX_SIGNAL];
};

RelayDevice *new_relay_device(const char *dir, const char *send, const char *recv,
                              bool server);

int register_interceptor(RelayDevice *rd, MemoryRegion *root,
                         hwaddr size, const char *name);
void intercept_region(RelayDevice *rd, unsigned bus_idx,
                      hwaddr base, hwaddr size,
                      const char *name);
MemoryRegion *intercept_region_detached(RelayDevice *rd, unsigned bus_idx,
                                        hwaddr base, hwaddr size,
                                        const char *name);

int create_requester(RelayDevice *rd, MemoryRegion *root,
                     const char *name);

MemoryRegion *get_interceptor_mr(RelayDevice *rd, unsigned bus_idx);

int register_in_signal(RelayDevice *rd, const char *name);
int register_out_signal(RelayDevice *rd, const char *name);

#endif
