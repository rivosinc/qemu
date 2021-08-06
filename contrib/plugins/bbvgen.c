/*
 * Copyright (c) 2021 by Rivos Inc.
 *
 * Generate Basic Block Vectors from an execution into a gzipped file
 * (bbv.gz by default). If provided, a single argument overrides the
 * output filename. Each time a new start PC is encountered when
 * translating a block, a new BB is generated for tracking. Each time
 * a BB is executed, its count is bumped by the number of instructions
 * it contains.
 *
 * If a block gets split by a new branch into it, a new BB is
 * generated to count executions via the new entrypoint. The original
 * BB will continue to accumulate counts for entry at the top/original
 * PC.
 *
 * A second argument should be provided to create a gzipped "info"
 * file to go along with the BBV. This file contains a line per
 * interval giving the initial PC, instruction count at the start, and
 * size of the interval. A final line gives the complete executed
 * instructions. Currently a BBV filename has to provided as the first
 * argument in order to activate this feature,
 * e.g. "libbbvgen.so,arg=bbv.gz,arg=bbvi.gz"
 *
 * NOTE: this plugin can be distributed separately and built against
 * QEMU headers. For simplicity we'll just add it to the existing
 * contrib/plugins area for now.
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
#include <fcntl.h>
#include <zlib.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static const char *filename = "bbv.gz";
static gzFile bbv_file;
static gzFile bbvi_file;

static GMutex lock;
static GHashTable *allblocks;

static uint64_t intv_length = 200000000; /* TODO: runtime argument */
static uint64_t cur_insns = 0;  /* interval duration tracker */
static uint64_t bb_id = 1;      /* bb ids are assigned once */

static uint32_t interval = 0;
static uint64_t intv_start_pc = -1;
static uint64_t total_insns = 0;

typedef struct {
    uint64_t id;
    uint64_t start_addr;
    uint64_t exec_count;
    unsigned long insns;
} BlockInfo;

static gint cmp_bbid(gconstpointer a, gconstpointer b)
{
    BlockInfo *ea = (BlockInfo *) a;
    BlockInfo *eb = (BlockInfo *) b;
    return (ea->id < eb->id) ? -1 : 1;
}

static void dump_interval(GList *blocks)
{
    gzprintf(bbv_file, "T");

    uint64_t count = 0;
    GList *it = blocks;
    while (it) {
       BlockInfo *rec = (BlockInfo *) it->data;
       gzprintf(bbv_file, ":%"PRIu64":%"PRIu64" ", rec->id, rec->exec_count);
       count += rec->exec_count;
       it = it->next;
    }
    g_assert(count == cur_insns);
    gzprintf(bbv_file, "\n");
}

static void filter_block(gpointer key,
                         gpointer value,
                         gpointer user_data)
{
    GList **blocks = (GList **)user_data;
    BlockInfo *cnt = (BlockInfo *) value;
    if (cnt->exec_count > 0) {
        *blocks = g_list_prepend(*blocks, value);
    }
}

static void zero_count(gpointer data,
                       gpointer user_data)
{
    BlockInfo *cnt = (BlockInfo *) data;
    cnt->exec_count = 0;
}

static void end_interval(void)
{
    // Create a list of just the blocks that executed during this
    // interval, then sort them by ID before emitting.
    GList *blocks = NULL;
    g_hash_table_foreach(allblocks, filter_block, (gpointer)&blocks);
    blocks = g_list_sort(blocks, cmp_bbid);

    // Generate the vector for this interval then zero the counts.
    dump_interval(blocks);
    g_list_foreach(blocks, zero_count, NULL);
    g_list_free(blocks);

    gzprintf(bbvi_file, "BBV %6u: start pc 0x%"PRIx64" @ icount %15"PRIu64" len %15"PRIu64"\n",
             interval, intv_start_pc, total_insns, cur_insns);
}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    end_interval();
    total_insns += cur_insns;
    gzclose_w(bbv_file);
    gzprintf(bbvi_file, "Total instructions: %"PRIu64"\n", total_insns);
    gzclose_w(bbvi_file);
}

static void plugin_init(void)
{
    allblocks = g_hash_table_new(NULL, g_direct_equal);
}

static void vcpu_tb_exec(unsigned int cpu_index, void *udata)
{
    // The callback has to run for every TB execution so we can detect
    // the end of an interval. Most of the time we just bail
    // immediately. Note that inline operations (counter increment)
    // run after callbacks.
    if (cur_insns < intv_length) {
      return;
    }

    end_interval();

    // Remember the PC that started each interval
    const uint64_t hash = (uint64_t) udata;
    BlockInfo *cnt = (BlockInfo *) g_hash_table_lookup(allblocks, (gconstpointer) hash);
    intv_start_pc = cnt->start_addr;

    // Start counting the next interval
    total_insns += cur_insns;
    cur_insns = 0;
    interval++;
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    BlockInfo *cnt;
    const uint64_t pc = qemu_plugin_tb_vaddr(tb);
    const size_t insns = qemu_plugin_tb_n_insns(tb);

    // Special case the initial PC since hereafter these are latched
    // on interval instruction count overflow in the tb_exec callback.
    if (intv_start_pc == -1) {
      intv_start_pc = pc;
    }

    // The start PC should uniquely identify a BB, even as previous
    // blocks are carved up by new branches into them.
    const uint64_t hash = pc >> 1;

    g_mutex_lock(&lock);
    cnt = (BlockInfo *) g_hash_table_lookup(allblocks, (gconstpointer) hash);
    if (cnt) {
      // Current assumption is a regenerated TB should exactly match
      // what we have in the hash table. We'll see if this ever turns
      // out to be false.
      g_assert(cnt->start_addr == pc && cnt->insns == insns);
    } else {
      cnt = g_new0(BlockInfo, 1);
      cnt->id = bb_id++;
      cnt->start_addr = pc;
      cnt->insns = insns;
      g_hash_table_insert(allblocks, (gpointer) hash, (gpointer) cnt);
    }
    g_mutex_unlock(&lock);

    // Run the callback to check for end-of-interval
    qemu_plugin_register_vcpu_tb_exec_cb(tb, vcpu_tb_exec,
                                         QEMU_PLUGIN_CB_NO_REGS,
                                         (void *)hash);

    // Bump the total and block exec counts. The order of registration
    // doesn't matter; inline operations run after callbacks.
    qemu_plugin_register_vcpu_tb_exec_inline(tb, QEMU_PLUGIN_INLINE_ADD_U64,
                                             &cur_insns, cnt->insns);
    qemu_plugin_register_vcpu_tb_exec_inline(tb, QEMU_PLUGIN_INLINE_ADD_U64,
                                             &cnt->exec_count, cnt->insns);
}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    if (argc > 0 && argv[0]) {
      filename = argv[0];
    }
    bbv_file = gzopen(filename, "wb9");
    if (bbv_file == Z_NULL) {
      return -1;
    }
    if (argc > 1 && argv[1]) {
      bbvi_file = gzopen(argv[1], "wb9");
      if (bbvi_file == Z_NULL) {
        gzclose_w(bbv_file);
        return -1;
      }
    }

    plugin_init();

    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
