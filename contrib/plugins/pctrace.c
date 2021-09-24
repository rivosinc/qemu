/*
 * Copyright (c) 2021 by Rivos Inc.
 *
 * Generate a full instruction trace with PC and disassembly. Since
 * the instruction info isn't available at exec time, the disassembly
 * is generated at TB translate time and saved away.
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */

#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <glib.h>
#include <zlib.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static uint64_t insn_count = 0;
static gzFile outfile = Z_NULL;

static GHashTable *dis;

static void plugin_init(void)
{
    dis = g_hash_table_new(NULL, g_direct_equal);
}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    gzclose_w(outfile);
}

static void vcpu_tb_exec(unsigned int vcpu_index, void *data)
{
    uint64_t addr = (uint64_t)data;
    gconstpointer key = (gconstpointer)(addr >> 1);
    GString *str = (GString *)g_hash_table_lookup(dis, key);
    g_assert(str);
    gzprintf(outfile, "%s", str->str);
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    uint64_t addr = qemu_plugin_tb_vaddr(tb);

    size_t n = qemu_plugin_tb_n_insns(tb);
    size_t i;

    GString *ds = g_string_new(NULL);

    for (i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        g_string_append_printf(ds,"0x%016"PRIx64"    %s\n",
                               qemu_plugin_insn_vaddr(insn),
                               qemu_plugin_insn_disas(insn));
        qemu_plugin_register_vcpu_insn_exec_inline(insn, QEMU_PLUGIN_INLINE_ADD_U64, &insn_count, 1);
    }

    qemu_plugin_register_vcpu_tb_exec_cb(tb, vcpu_tb_exec,
                                         QEMU_PLUGIN_CB_NO_REGS, (void *)addr);
    gpointer key = (gpointer)(addr >> 1);
    g_hash_table_insert(dis, key, ds);
}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    for (int i = 0; i < argc; i++) {
        char *opt = argv[i];
        g_autofree char **tokens = g_strsplit(opt, "=", 2);

        if (g_strcmp0(tokens[0], "out") == 0) {
            outfile = gzopen(tokens[1], "wb9");
            if (outfile == Z_NULL) {
                return -1;
            }
        } else {
            fprintf(stderr, "option parsing failed: %s\n", opt);
            return -1;
        }
    }

    if (outfile == Z_NULL) {
        fprintf(stderr, "A \"out=<path>\" argument must be supplied\n");
        return -1;
    }

    plugin_init();

    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
