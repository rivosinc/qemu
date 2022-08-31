/*
 * Rivos System useful constants
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

#ifndef HW_LUA_ENGINE
#define HW_LUA_ENGINE

#include "qom/object.h"

/*
 * Declare the object type and provide the client API
 * but don't force clients to include Lua headers.
 */

#define TYPE_LUA_ENGINE "lua-engine"
OBJECT_DECLARE_SIMPLE_TYPE(LuaEngine, LUA_ENGINE)

bool luaeng_register_address_space(LuaEngine *eng, MemoryRegion *root,
                                   const char *name);
void luaeng_arg_integer(LuaEngine *eng, uint64_t arg);
void luaeng_arg_string(LuaEngine *eng, const char *str);
void luaeng_play_script(LuaEngine *eng);

#endif
