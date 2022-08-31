/*
 * Lua script-playing device
 *
 * Copyright (C) 2022 Rivos Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "hw/qdev-properties.h"
#include "hw/sysbus.h"
#include "exec/memory.h"
#include "sysemu/runstate.h"
#include "qemu/coroutine.h"

#include <lua5.3/lua.h>
#include <lua5.3/lualib.h>
#include <lua5.3/lauxlib.h>

#include "hw/misc/lua-engine.h"

/*
 * Enhancements to consider:
 * - support device registers implemented in Lua; need to understand
 *   how vCPU threads interact with the Lua coroutine
 * - consider behavior if the machine resets - re-run the script?
 * - explore whether coroutine is a good way to go
 */

#define LUA_ENG_MAX_ASES (4)

struct LuaEngine {
    SysBusDevice parent_obj;

    Coroutine *co;
    uint64_t poll_period_ns;
    uint64_t poll_timeout_ns;

    MemTxAttrs attrs;
    AddressSpace *ases[LUA_ENG_MAX_ASES];
    unsigned num_ases;

    lua_State *lua;
    char *script;
    unsigned args;
    bool auto_start;
};

enum {
    RET_OK = 0,
    RET_FAIL = -1,
    RET_TIMEOUT = -2,
};

/*
 * Lua callback functions for `luaeng' namespace functions
 */

static int luaeng_bus_lookup(lua_State *L)
{
    LuaEngine *eng = lua_touserdata(L, lua_upvalueindex(1));
    const char *bus_name = luaL_checkstring(eng->lua, 1);
    int bus_index = -1;
    for (unsigned i = 0; i < eng->num_ases; i++) {
        if (!g_strcmp0(eng->ases[i]->name, bus_name)) {
            bus_index = i;
            break;
        }
    }
    lua_pushinteger(eng->lua, bus_index);
    return 1;
}

static int read_le(AddressSpace *as, MemTxAttrs attrs, hwaddr addr,
                           unsigned len, uint64_t *val)
{
    MemTxResult res = MEMTX_ERROR;
    uint64_t data = 0;

    switch (len) {
    case 1:
        data = address_space_ldub(as, addr, attrs, &res);
        break;
    case 2:
        data = address_space_lduw_le(as, addr, attrs, &res);
        break;
    case 4:
        data = address_space_ldl_le(as, addr, attrs, &res);
        break;
    case 8:
        data = address_space_ldq_le(as, addr, attrs, &res);
        break;
    default:
        break;
    }

    *val = data;
    return (res == MEMTX_OK) ? RET_OK : RET_FAIL;
}

static int read_be(AddressSpace *as, MemTxAttrs attrs, hwaddr addr,
                           unsigned len, uint64_t *val)
{
    MemTxResult res = MEMTX_ERROR;
    uint64_t data = 0;

    switch (len) {
    case 1:
        data = address_space_ldub(as, addr, attrs, &res);
        break;
    case 2:
        data = address_space_lduw_be(as, addr, attrs, &res);
        break;
    case 4:
        data = address_space_ldl_be(as, addr, attrs, &res);
        break;
    case 8:
        data = address_space_ldq_be(as, addr, attrs, &res);
        break;
    default:
        break;
    }

    *val = data;
    return (res == MEMTX_OK) ? RET_OK : RET_FAIL;
}

static int luaeng_read_le(lua_State *L)
{
    LuaEngine *eng = lua_touserdata(L, lua_upvalueindex(1));
    unsigned bus = luaL_checkinteger(eng->lua, 1);
    uint64_t addr = luaL_checkinteger(eng->lua, 2);
    unsigned len = luaL_checkinteger(eng->lua, 3);
    uint64_t val = 0;
    int res;

    if (bus < eng->num_ases) {
        res = read_le(eng->ases[bus], eng->attrs, addr, len, &val);
    } else {
        res = RET_FAIL;
    }

    lua_pushinteger(eng->lua, res);
    lua_pushinteger(eng->lua, val);
    return 2;
}

static int luaeng_read_be(lua_State *L)
{
    LuaEngine *eng = lua_touserdata(L, lua_upvalueindex(1));
    unsigned bus = luaL_checkinteger(eng->lua, 1);
    uint64_t addr = luaL_checkinteger(eng->lua, 2);
    unsigned len = luaL_checkinteger(eng->lua, 3);
    uint64_t val = 0;
    int res;

    if (bus < eng->num_ases) {
        res = read_be(eng->ases[bus], eng->attrs, addr, len, &val);
    } else {
        res = RET_FAIL;
    }

    lua_pushinteger(eng->lua, res);
    lua_pushinteger(eng->lua, val);
    return 2;
}

static int luaeng_poll(lua_State *L, bool big_endian)
{
    LuaEngine *eng = lua_touserdata(L, lua_upvalueindex(1));
    unsigned bus = luaL_checkinteger(eng->lua, 1);
    uint64_t addr = luaL_checkinteger(eng->lua, 2);
    unsigned len = luaL_checkinteger(eng->lua, 3);
    uint64_t mask = luaL_checkinteger(eng->lua, 4);
    uint64_t match = luaL_checkinteger(eng->lua, 5);
    uint64_t val = 0;
    int res = RET_FAIL;

    if (bus < eng->num_ases) {
        match &= mask;
        uint64_t start_ns = qemu_clock_get_ns(QEMU_CLOCK_REALTIME), elapsed;
        do {
            if (big_endian) {
                res = read_be(eng->ases[bus], eng->attrs, addr, len, &val);
            } else {
                res = read_le(eng->ases[bus], eng->attrs, addr, len, &val);
            }
            if (res != RET_OK) {
                break;
            }
            if ((val & mask) == match) {
                break;
            }
            elapsed = qemu_clock_get_ns(QEMU_CLOCK_REALTIME) - start_ns;
            if (elapsed > eng->poll_timeout_ns) {
                res = RET_TIMEOUT;
                break;
            }
            qemu_co_sleep_ns(QEMU_CLOCK_REALTIME, eng->poll_period_ns);
        } while (elapsed < eng->poll_timeout_ns);
    }

    lua_pushinteger(eng->lua, res);
    lua_pushinteger(eng->lua, val);
    return 2;
}

static int luaeng_poll_le(lua_State *L)
{
    return luaeng_poll(L, false);
}

static int luaeng_poll_be(lua_State *L)
{
    return luaeng_poll(L, true);
}

static int luaeng_write_le(lua_State *L)
{
    LuaEngine *eng = lua_touserdata(L, lua_upvalueindex(1));
    unsigned bus = luaL_checkinteger(eng->lua, 1);
    uint64_t addr = luaL_checkinteger(eng->lua, 2);
    unsigned len = luaL_checkinteger(eng->lua, 3);
    uint64_t val = luaL_checkinteger(eng->lua, 4);
    MemTxResult res = MEMTX_DECODE_ERROR;

    if (bus < eng->num_ases) {
        switch (len) {
        case 1:
            address_space_stb(eng->ases[bus], addr, val, eng->attrs, &res);
            break;
        case 2:
            address_space_stw_le(eng->ases[bus], addr, val, eng->attrs, &res);
            break;
        case 4:
            address_space_stl_le(eng->ases[bus], addr, val, eng->attrs, &res);
            break;
        case 8:
            address_space_stq_le(eng->ases[bus], addr, val, eng->attrs, &res);
            break;
        default:
            res = MEMTX_ERROR;
            break;
        }
        res = address_space_write(eng->ases[bus], addr, eng->attrs,
                                  &val, len);
    }

    lua_pushinteger(eng->lua, (res == MEMTX_OK) ? RET_OK : RET_FAIL);
    return 1;
}

static int luaeng_write_be(lua_State *L)
{
    LuaEngine *eng = lua_touserdata(L, lua_upvalueindex(1));
    unsigned bus = luaL_checkinteger(eng->lua, 1);
    uint64_t addr = luaL_checkinteger(eng->lua, 2);
    unsigned len = luaL_checkinteger(eng->lua, 3);
    uint64_t val = luaL_checkinteger(eng->lua, 4);
    MemTxResult res = MEMTX_DECODE_ERROR;

    if (bus < eng->num_ases) {
        switch (len) {
        case 1:
            address_space_stb(eng->ases[bus], addr, val, eng->attrs, &res);
            break;
        case 2:
            address_space_stw_be(eng->ases[bus], addr, val, eng->attrs, &res);
            break;
        case 4:
            address_space_stl_be(eng->ases[bus], addr, val, eng->attrs, &res);
            break;
        case 8:
            address_space_stq_be(eng->ases[bus], addr, val, eng->attrs, &res);
            break;
        default:
            res = MEMTX_ERROR;
            break;
        }
    }

    lua_pushinteger(eng->lua, (res == MEMTX_OK) ? RET_OK : RET_FAIL);
    return 1;
}

static int luaeng_set_attrs(lua_State *L)
{
    LuaEngine *eng = lua_touserdata(L, lua_upvalueindex(1));
    unsigned requester = luaL_checkinteger(eng->lua, 1);
    unsigned secure = luaL_checkinteger(eng->lua, 2);
    /* Currently a limited number of attributes are exposed to Lua */
    eng->attrs.unspecified = 0;
    eng->attrs.requester_id = requester;
    eng->attrs.secure = secure ? 1 : 0;
    return 0;
}

static int luaeng_clear_attrs(lua_State *L)
{
    LuaEngine *eng = lua_touserdata(L, lua_upvalueindex(1));
    eng->attrs = MEMTXATTRS_UNSPECIFIED;
    return 0;
}

static int luaeng_set_poll_rate(lua_State *L)
{
    LuaEngine *eng = lua_touserdata(L, lua_upvalueindex(1));
    eng->poll_period_ns = luaL_checkinteger(eng->lua, 1);
    return 0;
}

static int luaeng_set_poll_timeout(lua_State *L)
{
    LuaEngine *eng = lua_touserdata(L, lua_upvalueindex(1));
    eng->poll_timeout_ns = luaL_checkinteger(eng->lua, 1);
    return 0;
}

static int luaeng_sleep(lua_State *L)
{
    LuaEngine *eng = lua_touserdata(L, lua_upvalueindex(1));
    uint64_t sleep_ns = luaL_checkinteger(eng->lua, 1);
    qemu_co_sleep_ns(QEMU_CLOCK_REALTIME, sleep_ns);
    return 0;
}

static int luaeng_exit(lua_State *L)
{
    LuaEngine *eng = lua_touserdata(L, lua_upvalueindex(1));
    int code = luaL_checkinteger(eng->lua, 1);
    error_report("*** exit triggered by Lua script (code %d) ***\n", code);
    exit(code);
}

static const luaL_Reg luaeng_table[] = {
    {"lookup", luaeng_bus_lookup},
    {"read", luaeng_read_le},
    {"write", luaeng_write_le},
    {"poll", luaeng_poll_le},
    {"read_le", luaeng_read_le},
    {"write_le", luaeng_write_le},
    {"poll_le", luaeng_poll_le},
    {"read_be", luaeng_read_be},
    {"write_be", luaeng_write_be},
    {"poll_be", luaeng_poll_be},
    {"set_attrs", luaeng_set_attrs},
    {"clear_attrs", luaeng_clear_attrs},
    {"set_poll_ns", luaeng_set_poll_rate},
    {"set_poll_timeout_ns", luaeng_set_poll_timeout},
    {"sleep", luaeng_sleep},
    {"exit", luaeng_exit},
    {NULL, NULL},
};

/*
 * Device registration and setup
 */

static void luaeng_init(Object *obj)
{
    LuaEngine *eng = LUA_ENGINE(obj);

    eng->attrs = MEMTXATTRS_UNSPECIFIED;
    eng->poll_period_ns = 1000000;       /* 1ms poll period */
    eng->poll_timeout_ns = 5000000000;   /* 5s timeout */

    eng->lua = luaL_newstate();
    luaL_openlibs(eng->lua);

    /* Register the function table into the 'luaeng' global namespace */
    luaL_newlibtable(eng->lua, luaeng_table);
    lua_pushlightuserdata(eng->lua, eng);
    luaL_setfuncs(eng->lua, luaeng_table, 1);
    lua_setglobal(eng->lua, "luaeng");

    /* Put a new table at the top of the stack for arguments */
    lua_newtable(eng->lua);
}

static void coroutine_fn lua_script_player(void *arg)
{
    LuaEngine *eng = arg;

    lua_pushstring(eng->lua, eng->script);
    lua_seti(eng->lua, -2, 0);
    lua_setglobal(eng->lua, "arg");

    if (luaL_dofile(eng->lua, eng->script) != 0) {
        error_report("*** Lua script failed ***\n");
        exit(EXIT_FAILURE);
    }
}

static void luaeng_vm_state_change(void *opaque, bool running,
                                   RunState state)
{
    LuaEngine *eng = opaque;

    if (state == RUN_STATE_RUNNING) {
        eng->co = qemu_coroutine_create(lua_script_player, eng);
        qemu_coroutine_enter(eng->co);
    }
}

static void luaeng_realize(DeviceState *dev, Error **errp)
{
    LuaEngine *eng = LUA_ENGINE(dev);

    if (eng->script && eng->auto_start) {
        qemu_add_vm_change_state_handler(luaeng_vm_state_change, dev);
    }
}

static Property luaeng_properties[] = {
    DEFINE_PROP_STRING("script", LuaEngine, script),
    DEFINE_PROP_BOOL("auto-start", LuaEngine, auto_start, true),
    DEFINE_PROP_END_OF_LIST(),
};

static void luaeng_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    device_class_set_props(dc, luaeng_properties);
    dc->realize = luaeng_realize;
}

static const TypeInfo luaeng_device_info = {
    .name = TYPE_LUA_ENGINE,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(LuaEngine),
    .instance_init = luaeng_init,
    .class_init = luaeng_class_init,
};

static void luaeng_register_types(void)
{
    type_register_static(&luaeng_device_info);
}

type_init(luaeng_register_types)

/*
 * Client interface: AddressSpace setup and script playback
 */

bool luaeng_register_address_space(LuaEngine *eng, MemoryRegion *root,
                                   const char *name)
{
    if (eng->num_ases >= LUA_ENG_MAX_ASES) {
        return false;
    }

    AddressSpace *as = g_new0(AddressSpace, 1);
    address_space_init(as, root, name);
    eng->ases[eng->num_ases++] = as;
    return true;
}

void luaeng_arg_integer(LuaEngine *eng, uint64_t arg)
{
    lua_pushinteger(eng->lua, arg);
    lua_seti(eng->lua, -2, ++eng->args);
}

void luaeng_arg_string(LuaEngine *eng, const char *str)
{
    lua_pushstring(eng->lua, str);
    lua_seti(eng->lua, -2, ++eng->args);
}

/*
 * luaeng_play_script - allow the script to be started up at an
 * arbitrary time other than the VM's transition to running if the
 * auto-start property was set to false.
 */
void luaeng_play_script(LuaEngine *eng)
{
    if (eng->script && !eng->auto_start) {
        eng->co = qemu_coroutine_create(lua_script_player, eng);
        qemu_coroutine_enter(eng->co);
    }
}
