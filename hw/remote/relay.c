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

#include "hw/remote/relay.h"

#include "qemu/option.h"
#include "qemu/config-file.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "qapi/error.h"
#include "hw/irq.h"
#include "hw/qdev-properties-system.h"
#include "exec/memory.h"
#include "trace.h"

typedef enum {
    CMD_READ            = 1,
    CMD_WRITE           = 2,
    CMD_SIGNAL          = 3,
} RelayCmd_t;

typedef union RelayCmdAttrs {
    MemTxAttrs attrs;
    uint32_t   raw;
} RelayCmdAttrs;
static_assert(sizeof(RelayCmdAttrs) == sizeof(uint32_t));

/* Use a single small-ish packet for all command types */
typedef struct RelayRequest {
    uint8_t     cmd;
    uint8_t     bus;
    uint8_t     len;
    uint8_t     _pad[1];
    uint32_t    attrs;          /* MemTxAttrs is 24B */
    uint64_t    addr;           /* (or signal) */
    uint64_t    inline_data;    /* (or signal value) */
} __attribute__((__packed__)) RelayRequest;

typedef struct RelayResponse {
    uint64_t    inline_data;    /* only for reads */
    uint32_t    result;
} __attribute__((__packed__)) RelayResponse;

/*
 * The originator transfers commands and responses on its 'send' socket,
 * and knows the response size based on the command just sent.
 */

static int send_command(RelayDevice *rd, uint8_t *req, unsigned size)
{
    int ret = qemu_chr_fe_write_all(&rd->send, req, size);
    if (ret != size) {
        ret = (ret < 0) ? -errno : -EIO;
    } else {
        ret = 0;
    }
    return ret;
}

static int recv_response(RelayDevice *rd, uint8_t *rsp, unsigned size)
{
    int ret = qemu_chr_fe_read_all(&rd->send, rsp, size);
    if (ret != size) {
        ret = (ret < 0) ? -errno : -EIO;
    } else {
        ret = 0;
    }
    return ret;
}

/*
 * Responders receive commands and respond to them on their 'recv'
 * socket, and assume all commands are complete RelayRequests.
 */
static int send_response(RelayDevice *rd, uint8_t *rsp, unsigned size)
{
    int ret = qemu_chr_fe_write_all(&rd->recv, rsp, size);
    if (ret != size) {
        ret = (ret < 0) ? -errno : -EIO;
    } else {
        ret = 0;
    }
    return ret;
}

static void propagate_gpio(void *opaque, int signo, int level)
{
    RelayDevice *rd = opaque;
    RelayRequest req = { .cmd = CMD_SIGNAL, .addr = signo,
                         .inline_data = level };

    trace_relay_signal(signo, level);
    int ret = send_command(rd, (uint8_t *)&req, sizeof(req));
    if (ret < 0) {
        error_report("relay: gpio send failure (%d)", ret);
        exit(EXIT_FAILURE);
    }
}

/*
 * relay_serialized_request - perform a read or write across the relay.
 * Release the iothread lock because the far side might need to send a
 * command back to this side before responding. While the BQL is
 * released, hold a mutex for this relay to avoid potential of command
 * responses getting interleaved. Decoupled requests and responses are
 * not supported.
 */
static void relay_serialized_request(RelayDevice *rd,
                                     RelayRequest *req,
                                     RelayResponse *rsp)
{
    bool locked = qemu_mutex_iothread_locked();
    if (locked) {
        qemu_mutex_unlock_iothread();
    }
    qemu_mutex_lock(&rd->mutex);
    int ret = send_command(rd, (uint8_t *)req, sizeof(*req));
    if (ret < 0) {
        error_report("relay: command send failure (%d)", ret);
        exit(EXIT_FAILURE);
    }

    ret = recv_response(rd, (uint8_t *)rsp, sizeof(*rsp));
    if (ret < 0) {
        error_report("relay: response receive failure (%d)", ret);
        exit(EXIT_FAILURE);
    }
    qemu_mutex_unlock(&rd->mutex);
    if (locked) {
        qemu_mutex_lock_iothread();
    }
}

static MemTxResult relay_rgn_read_with_attrs(void *opaque,
                                             hwaddr addr,
                                             uint64_t *val,
                                             unsigned size,
                                             MemTxAttrs attrs)
{
    MemoryRegion *mr = MEMORY_REGION(opaque);
    RelayDevice *rd = RELAY_DEVICE(mr->owner);
    BusIntercept *bi = container_of(mr, BusIntercept, intercept);
    unsigned bus_idx = bi - rd->intercept;
    RelayCmdAttrs cmdattrs = { .attrs = attrs};
    RelayRequest req = { .cmd = CMD_READ, .addr = addr,
                         .bus = bus_idx, .len = size,
                         .attrs = cmdattrs.raw };
    RelayResponse rsp;

    relay_serialized_request(rd, &req, &rsp);
    *val = rsp.inline_data;
    trace_relay_read(bus_idx, size, addr, *val);

    return rsp.result;
}

static MemTxResult relay_rgn_write_with_attrs(void *opaque,
                                              hwaddr addr,
                                              uint64_t val,
                                              unsigned size,
                                              MemTxAttrs attrs)
{
    MemoryRegion *mr = MEMORY_REGION(opaque);
    RelayDevice *rd = RELAY_DEVICE(mr->owner);
    BusIntercept *bi = container_of(mr, BusIntercept, intercept);
    unsigned bus_idx = bi - rd->intercept;
    RelayCmdAttrs cmdattrs = { .attrs = attrs};
    RelayRequest req = { .cmd = CMD_WRITE, .addr = addr,
                         .inline_data = val,
                         .bus = bus_idx, .len = size,
                         .attrs = cmdattrs.raw };
    RelayResponse rsp;

    trace_relay_write(bus_idx, size, addr, val);
    relay_serialized_request(rd, &req, &rsp);

    return rsp.result;
}

/*
 * For RACL and C-bit support, attributes are passed across the relay.
 */
static const MemoryRegionOps relay_mem_ops = {
    .read_with_attrs = relay_rgn_read_with_attrs,
    .write_with_attrs = relay_rgn_write_with_attrs,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 8,
    },
    .impl = {
        .min_access_size = 1,
        .max_access_size = 8,
    },
};

/*
 * create_requester - creates an AddressSpace to associate with read
 * and write commands received from the peer. Note that since there's
 * no support for bus ID remapping across the relay, both sides need
 * to create their requesters and inteceptors in the same order.
 */
int create_requester(RelayDevice *rd, MemoryRegion *root, const char *name)
{
    if (rd->num_rqst == RELAY_MAX_REQUESTER) {
        return -1;
    }
    int bus = rd->num_rqst++;
    BusRequester *br = &rd->requester[bus];
    br->as = g_malloc0(sizeof(AddressSpace));
    /* 'name' is copied */
    address_space_init(br->as, root, name);
    return bus;
}

/*
 * register_interceptor - takes note of a new "bus" to potentially
 * add subregions for relay to the peer. Create an IO region covering
 * the entire bus, that generates relay traffic in its read and write
 * IO handlers. Don't actually coverany portion of the root MR until
 * 'intercept_region' calls establish regions to intercept and relay.
 */
int register_interceptor(RelayDevice *rd, MemoryRegion *root,
                         hwaddr size, const char *name)
{
    if (rd->num_rcvr == RELAY_MAX_RECEIVER) {
        return -1;
    }
    int bus = rd->num_rcvr++;
    BusIntercept *bi = &rd->intercept[bus];
    bi->root = root;
    /* 'name' is copied */
    memory_region_init_io(&bi->intercept, OBJECT(rd), &relay_mem_ops,
                          &bi->intercept, name, size);
    return bus;
}

/*
 * intercept_region - carve out a specified subregion of the
 * intercepted bus using an alias onto the intercept MR, which will
 * forward MMIO accesses to the peer. Intercepted regions are given the
 * default priority (0) and will take precedence over any existing
 * direct subregions with 0 or lower priority.
 *
 * Clients are expected to leave non-intercepted holes as necessary,
 * or use priority > 0 in direct subregions that overlap and should not
 * be intercepted.
 */
void intercept_region(RelayDevice *rd, unsigned bus_idx,
                      hwaddr base, hwaddr size,
                      const char *name)
{
    BusIntercept *bi = &rd->intercept[bus_idx];
    MemoryRegion *mr = g_new0(MemoryRegion, 1);
    /* 'name' is copied: */
    memory_region_init_alias(mr, OBJECT(rd), name, &bi->intercept, base, size);
    memory_region_add_subregion(bi->root, base, mr);
}

/*
 * signal from the local system to relay
 */
int register_in_signal(RelayDevice *rd, const char *name)
{
    if (rd->num_ins == RELAY_MAX_SIGNAL) {
        return -1;
    }

    return rd->num_ins++;
}

/*
 * signal to the local system to drive
 */
int register_out_signal(RelayDevice *rd, const char *name)
{
    if (rd->num_outs == RELAY_MAX_SIGNAL) {
        return -1;
    }

    return rd->num_outs++;
}

/*
 * intercept_region_detached: gives the caller a chance to plumb a
 * path to the relay from somewhere other than the "root" bus.
 */
MemoryRegion *intercept_region_detached(RelayDevice *rd, unsigned bus_idx,
                                        hwaddr base, hwaddr size,
                                        const char *name)
{
    BusIntercept *bi = &rd->intercept[bus_idx];
    MemoryRegion *mr = g_new0(MemoryRegion, 1);
    memory_region_init_alias(mr, OBJECT(rd), name, &bi->intercept, base, size);
    return mr;
}

MemoryRegion *get_interceptor_mr(RelayDevice *rd, unsigned bus_idx)
{
    BusIntercept *bi = &rd->intercept[bus_idx];
    return bi->root;
}

static int relay_can_receive(void *opaque)
{
    return sizeof(RelayRequest);
}

static void relay_receive(void *opaque, const uint8_t *buf, int size)
{
    RelayDevice *rd = opaque;
    RelayRequest *msg = (RelayRequest *)buf;
    assert(size == sizeof(RelayRequest));
    switch (msg->cmd) {
    case CMD_READ: {
        RelayResponse rsp = {};
        if ((msg->len > 8) || (msg->bus >= rd->num_rqst)) {
            rsp.result = MEMTX_ERROR;
        } else {
            BusRequester *br = &rd->requester[msg->bus];
            RelayCmdAttrs cmdattrs = { .raw = msg->attrs};
            /* Currently not doing bus ID remapping */
            rsp.result = address_space_read(br->as, msg->addr,
                cmdattrs.attrs, (uint8_t *)&rsp.inline_data, msg->len);
        }
        if (rsp.result != MEMTX_OK) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "relay: bad read on %u of 0x%lx x %d -> %lx\n",
                          msg->bus, msg->addr, msg->len, rsp.inline_data);
        }
        int ret = send_response(rd, (uint8_t *)&rsp, sizeof(rsp));
        if (ret < 0) {
            error_report("relay: read respond failure (%d)", ret);
            exit(EXIT_FAILURE);
        }
        break;
    }
    case CMD_WRITE: {
        RelayResponse rsp = {};
        if ((msg->len > 8) || (msg->bus >= rd->num_rqst)) {
            rsp.result = MEMTX_ERROR;
        } else {
            BusRequester *br = &rd->requester[msg->bus];
            RelayCmdAttrs cmdattrs = { .raw = msg->attrs};
            /* Currently not doing bus ID remapping */
            rsp.result = address_space_write(br->as, msg->addr,
                cmdattrs.attrs, (uint8_t *)&msg->inline_data, msg->len);
        }
        if (rsp.result != MEMTX_OK) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "relay: bad write on %u of 0x%lx x %d -> %lx\n",
                          msg->bus, msg->addr, msg->len, msg->inline_data);
        }
        int ret = send_response(rd, (uint8_t *)&rsp, sizeof(rsp));
        if (ret < 0) {
            error_report("relay: response send failure (%d)", ret);
            exit(EXIT_FAILURE);
        }
        break;
    }
    case CMD_SIGNAL: {
        /* Currently not doing signal ID remapping */
        unsigned signo = (unsigned)msg->addr;
        if (signo < rd->num_outs) {
            qemu_irq irq = rd->out[signo];
            qemu_set_irq(irq, (int)msg->inline_data);
        }
        break;
    }
    default:
        error_report("relay: unrecognized command");
        exit(EXIT_FAILURE);
    }
}

static void relay_event(void *opaque, QEMUChrEvent event)
{
    switch (event) {
    case CHR_EVENT_CLOSED:
        error_report("relay: connection lost; exitting");
        exit(EXIT_FAILURE);
    default:
        break;
    }
}

static void relay_realize(DeviceState *dev, Error **errp)
{
    RelayDevice *rd = RELAY_DEVICE(dev);

    qemu_mutex_init(&rd->mutex);

    qdev_init_gpio_in(dev, propagate_gpio, RELAY_MAX_SIGNAL);
    qdev_init_gpio_out(dev, rd->out, RELAY_MAX_SIGNAL);

    qemu_chr_fe_set_handlers(&rd->recv, relay_can_receive,
                             relay_receive, relay_event, NULL,
                             rd, NULL, true);
}

static Property relay_properties[] = {
    DEFINE_PROP_CHR("send", RelayDevice, send),
    DEFINE_PROP_CHR("recv", RelayDevice, recv),
    DEFINE_PROP_END_OF_LIST(),
};

static void relay_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    device_class_set_props(dc, relay_properties);
    dc->realize = relay_realize;
}

static const TypeInfo relay_device_info = {
    .name = TYPE_RELAY_DEVICE,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(RelayDevice),
    .class_init = relay_class_init,
};

static void relay_register_types(void)
{
    type_register_static(&relay_device_info);
}

type_init(relay_register_types)

static Chardev *make_relay_chardev(const char *dir, const char *name, bool server)
{
    QemuOpts *opts = qemu_opts_create(qemu_find_opts("chardev"), name,
                                      1, &error_fatal);
    char *path;

    int ret = asprintf(&path, "%s/%s", dir, name);
    if (ret <= 0) {
        return NULL;
    }
    qemu_opt_set(opts, "backend", "socket", &error_fatal);
    qemu_opt_set(opts, "path", path, &error_abort);
    if (server) {
        qemu_opt_set(opts, "server", "on", &error_fatal);
        qemu_opt_set(opts, "wait", "off", &error_fatal);
    }
    Chardev *chr = qemu_chr_new_from_opts(opts, NULL, &error_fatal);
    qemu_opts_del(opts);
    free(path);
    return chr;
}

/*
 * new_relay_device - create one or two socket character devices
 * for communication with a second process. A "send" channel is
 * used for issuing commands and receiving responses; a "recv"
 * channel is used for receiving commands and sending responses.
 * A directory prefix is supplied for constructing a path for
 * the unix domain sockets. When "server" is true, any created
 * chardevs will have 'server=on' and 'wait=off' set in the device
 * properties.
 */
RelayDevice *new_relay_device(const char *dir, const char *send,
                              const char *recv, bool server)
{
    DeviceState *dev = qdev_new(TYPE_RELAY_DEVICE);
    Chardev *sender = NULL, *receiver = NULL;

    if (send) {
        sender = make_relay_chardev(dir, send, server);
        qdev_prop_set_chr(dev, "send", sender);
    }
    if (recv) {
        receiver = make_relay_chardev(dir, recv, server);
        qdev_prop_set_chr(dev, "recv", receiver);
    }

    if ((send && !sender) || (recv && !receiver)) {
        object_unref(OBJECT(sender));
        object_unref(OBJECT(receiver));
        object_unref(OBJECT(dev));
        return NULL;
    } else {
        sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_abort);
        return RELAY_DEVICE(dev);
    }
}
