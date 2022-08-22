/*
 * Copyright (c) 2021-2022 by Rivos Inc.
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
 * size of the interval. After this line, the top 10 basic blocks (by
 * dynamic instruction count) are listed with PC and instruction
 * count. At the end of execution, another line gives the complete
 * executed instructions count, followed by a dump of the top 10
 * blocks across the entire run. Currently a BBV filename has to
 * provided as the first argument in order to activate this feature,
 * e.g. "libbbvgen.so,arg=bbv.gz,arg=bbvi.gz"
 *
 * NOTE: this plugin can be distributed separately and built against
 * QEMU headers. For simplicity we'll just add it to the existing
 * contrib/plugins area for now.
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */

#include <sys/syscall.h>
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

static char bbv_path[PATH_MAX] = {0};
static gzFile bbv_file = Z_NULL;
static char bbvi_path[PATH_MAX] = {0};
static gzFile bbvi_file = Z_NULL;

static GMutex lock;
static GHashTable *allblocks;

static unsigned hot_count = 10; /* override using QEMU_BBV_BLOCKS */
static uint64_t intv_length = 200000000; /* override using QEMU_BBV_INTERVAL */

static uint64_t cur_insns = 0;  /* interval duration tracker */
static uint64_t bb_id = 1;      /* bb ids are assigned once */
static uint64_t drift = 0;      /* track drift of interval start */

static uint32_t interval = 0;
static uint64_t intv_start_pc = -1;
static uint64_t total_insns = 0;

static int64_t clone_syscall_num = -1;

static void outfile_init(void);

// BlockInfo records details about a particular TCG translation block
// and its execution stats. The '*_count' members track the number of
// instructions executed as part of this TB (block executions * block
// instruction count).
typedef struct {
    uint64_t id;                // ID assigned for BB
    uint64_t start_addr;        // starting PC of this TB
    uint64_t last_pc;           // PC of the last inst in the TB
    uint64_t exec_count;        // scaled count (#exec * #insns) for
                                // this TB in the current interval
    uint64_t total_count;       // total scaled count for this TB
    uint32_t insns;             // number of insns in the TB
} BlockInfo;

static gint cmp_bbid(gconstpointer a, gconstpointer b)
{
    BlockInfo *ea = (BlockInfo *) a;
    BlockInfo *eb = (BlockInfo *) b;
    return (ea->id < eb->id) ? -1 : 1;
}

static gint cmp_exec_count(gconstpointer a, gconstpointer b)
{
    BlockInfo *ea = (BlockInfo *) a;
    BlockInfo *eb = (BlockInfo *) b;
    return ea->exec_count > eb->exec_count ? -1 : 1;
}

static void reset_block(gpointer key, gpointer value, gpointer user_data)
{
    BlockInfo* blkinfo = (BlockInfo*)value;
    blkinfo->exec_count = 0;
    blkinfo->total_count = 0;
};

// Called on the child process after a fork.
// Resets counts and opens new output files with the child pid
// appended to the filename.
static void handle_fork_child(void)
{
    pid_t me = getpid();
    if (bbv_file) {
        char extension[100];
        int extlen = snprintf(extension, sizeof(extension), ".%u", me);
        assert(extlen > 0);  // sanity-check
        // Make sure we don't blow our path length:
        assert(strlen(bbv_path) + extlen < sizeof(bbv_path));
        strncat(bbv_path, extension, extlen);
    }
    if (bbvi_file) {
        char extension[100];
        int extlen = snprintf(extension, sizeof(extension), ".%u", me);
        assert(extlen > 0);  // sanity-check
        // Make sure we don't blow our path length:
        assert(strlen(bbvi_path) + extlen < sizeof(bbvi_path));
        strncat(bbvi_path, extension, extlen);
    }

    // Zlib doesn't seem to have a way to tear down local state +
    // close the underlying file descriptor, which we would prefer
    // (since the parent process will continue writing to this
    // file). Instead, we leak.

    // TODO: Find a way to not leak memory + open fd
    outfile_init();

    // Reset counts
    cur_insns = 0;
    drift = 0;
    interval = 0;
    total_insns = 0;
    g_mutex_lock(&lock);
    g_hash_table_foreach(allblocks, reset_block, NULL);
    g_mutex_unlock(&lock);
}

static void vcpu_syscall_ret(qemu_plugin_id_t id, unsigned int vcpu_idx,
                             int64_t num, int64_t ret)
{
    if (num != clone_syscall_num || ret != 0) {
        return;
    }
    // We are officialy the child process in a fork that's returning.
    handle_fork_child();
}

static void dump_interval(GList *blocks)
{
    gzprintf(bbv_file, "T");

    uint64_t count = 0;
    GList *it = blocks;
    while (it) {
       BlockInfo *blkinfo = (BlockInfo *) it->data;
       gzprintf(bbv_file, ":%"PRIu64":%"PRIu64" ", blkinfo->id, blkinfo->exec_count);
       count += blkinfo->exec_count;
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
    BlockInfo *blkinfo = (BlockInfo *) value;
    if (blkinfo->exec_count > 0) {
        *blocks = g_list_prepend(*blocks, value);
    }
}

static void filter_block_final(gpointer key,
                               gpointer value,
                               gpointer user_data)
{
    GList **blocks = (GList **)user_data;
    BlockInfo *blkinfo = (BlockInfo *) value;
    // Move the total_count into exec_count, so the final top blocks
    // summary can reuse cmp_exec_count and emit_hot_blocks.
    blkinfo->exec_count = blkinfo->total_count;
    if (blkinfo->exec_count > 0) {
        *blocks = g_list_prepend(*blocks, value);
    }
}

static void latch_count(gpointer data,
                        gpointer user_data)
{
    BlockInfo *blkinfo = (BlockInfo *) data;
    // Accumulate the total count for the final summary; reset the
    // exec count for the next interval.
    blkinfo->total_count += blkinfo->exec_count;
    blkinfo->exec_count = 0;
}

static void emit_hot_blocks(GList *blocks, unsigned count, uint64_t region_count, unsigned indent)
{
    GList *it = blocks;
    for (unsigned i = 0; (i < count) && it; i++, it = it->next) {
        BlockInfo *blkinfo = (BlockInfo *)it->data;
        if (i > 0) {
            gzprintf(bbvi_file, ",\n");
        }
        gzprintf(bbvi_file, "%*s{\"pc\" : %"PRIu64", \"len\" : %lu, \"icount\" : %"PRIu64", \"pct\": %.2f }",
                 indent, " ", blkinfo->start_addr, blkinfo->insns, blkinfo->exec_count,
                 (float)blkinfo->exec_count*100 / region_count);
    }
    gzprintf(bbvi_file, "\n");
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

    if (bbvi_file != Z_NULL) {
        if (interval > 0) {
            gzprintf(bbvi_file, ",\n");
        }
        gzprintf(bbvi_file, "        {\n            \"index\" : %u, \"pc\" : %"PRIu64", \"len\" : %"PRIu64
                 ", \"icount\" : %"PRIu64", \"blocks\" : [\n", interval, intv_start_pc,
                 cur_insns, total_insns);

        // Print the top N blocks w/ PC and instruction count
        blocks = g_list_sort(blocks, cmp_exec_count);
        emit_hot_blocks(blocks, hot_count, cur_insns, 16);
        gzprintf(bbvi_file, "            ]\n        }");
    }

    g_list_foreach(blocks, latch_count, NULL);
    g_list_free(blocks);

    // Get ready to start counting the next interval. No harm in the
    // case where we're closing out a final, partial interval.
    total_insns += cur_insns;
    cur_insns = 0;
    interval++;
}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    // Flush the partial interval that was in progress when the
    // program exited.
    end_interval();

    gzclose_w(bbv_file);

    // Write out some details covering the entire execution
    if (bbvi_file != Z_NULL) {
        gzprintf(bbvi_file, "\n    ],\n");
        gzprintf(bbvi_file, "    \"instructions\" : %"PRIu64",\n", total_insns);

        // Pull the top blocks from the entire run and emit_hot_blocks
        GList *blocks = NULL;
        g_hash_table_foreach(allblocks, filter_block_final, (gpointer)&blocks);
        blocks = g_list_sort(blocks, cmp_exec_count);
        gzprintf(bbvi_file, "    \"blocks\" : [\n");
        emit_hot_blocks(blocks, hot_count, total_insns, 8);
        bool more = true;
        gzprintf(bbvi_file, "    ]%s\n", more ? "," : "");
        g_list_free(blocks);
        blocks = NULL;

        // Dump a sorted list of block IDs with block info
        g_hash_table_foreach(allblocks, filter_block, (gpointer)&blocks);
        blocks = g_list_sort(blocks, cmp_bbid);
        gzprintf(bbvi_file, "    \"ids\" : [\n");
        GList *it = blocks;
        for (unsigned i = 0; it; i++, it = it->next) {
            BlockInfo *blkinfo = (BlockInfo *)it->data;
            if (i > 0) {
                gzprintf(bbvi_file, ",\n");
            }
            gzprintf(bbvi_file, "        {\"id\" : %"PRIu64", \"pc\" : %"PRIu64", \"insns\" : %lu }",
                    blkinfo->id, blkinfo->start_addr, blkinfo->insns);
        }
        gzprintf(bbvi_file, "\n");
        more = false;
        gzprintf(bbvi_file, "    ]%s\n", more ? "," : "");
        g_list_free(blocks);

        gzprintf(bbvi_file, "}\n");
        gzclose_w(bbvi_file);
    }
}

static void outfile_init(void)
{
    if (bbv_path[0]) {
        bbv_file = gzopen(bbv_path, "wb9");
        if (bbv_file == Z_NULL) {
            printf("Can't open %s\n", bbv_path);
        }
        assert(bbv_file != Z_NULL);
    }
    if (bbvi_path[0]) {
        bbvi_file = gzopen(bbvi_path, "wb9");
        if (bbv_file == Z_NULL) {
            printf("Can't open %s\n", bbvi_path);
        }
        assert(bbvi_file != Z_NULL);
        gzprintf(bbvi_file, "{\n    \"source\" : \"qemu-bbvgen\",\n");
        gzprintf(bbvi_file, "    \"intervals\" : [\n");
    }
}

static void plugin_init(const char* target)
{
    if (g_strcmp0(target, "riscv64") == 0) {
        clone_syscall_num = 220;
    } else {
        printf("%s:%d: Unhandled target! Please fix!\n", __FILE__, __LINE__);
    }

    allblocks = g_hash_table_new(NULL, g_direct_equal);
}

static void vcpu_tb_exec(unsigned int cpu_index, void *udata)
{
    BlockInfo *blkinfo = (BlockInfo *) udata;

    // The callback has to run for every TB execution so we can detect
    // the end of an interval. Most of the time we just bail
    // immediately. Note that inline operations (counter increment)
    // run after callbacks, which means we're evaluating the number of
    // instructions executed up through the *previous* TB.
    if (cur_insns + drift < intv_length) {
        return;
    }

    // Track drift due to ending intervals on block boundaries. We
    // want interval starts to stay close to (intv_num * intv_length).
    drift = (cur_insns + drift) - intv_length;

    // Emit all the interval stats and reset the block counts
    end_interval();

    // Remember the PC that started each interval
    intv_start_pc = blkinfo->start_addr;
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    BlockInfo *blkinfo;
    const uint64_t pc = qemu_plugin_tb_vaddr(tb);
    const size_t insns = qemu_plugin_tb_n_insns(tb);

    // Special case the initial PC since hereafter these are latched
    // on interval instruction count overflow in the tb_exec callback.
    if (intv_start_pc == -1) {
        intv_start_pc = pc;
    }

    // The start PC should uniquely identify a BB, even as new blocks
    // get carved out by new branches into the middle of existing ones.
    // If a new, shorter block "B" is created by a branch into the
    // middle of an existing one "A", block B will receive counts only
    // for execution paths that branch directly to B and skip the start
    // of block A. Block A will continue to receive counts for
    // executions that enter at its start PC.
    const uint64_t hash = pc;

    g_mutex_lock(&lock);
    blkinfo = (BlockInfo *) g_hash_table_lookup(allblocks, (gconstpointer) hash);
    if (blkinfo) {
        // Current assumption is a regenerated TB should exactly match
        // what we have in the hash table. We'll see if this ever
        // turns out to be false.
        g_assert(blkinfo->start_addr == pc && blkinfo->insns == insns);
    } else {
        blkinfo = g_new0(BlockInfo, 1);
        blkinfo->id = bb_id++;
        blkinfo->start_addr = pc;
        blkinfo->insns = insns;
        g_hash_table_insert(allblocks, (gpointer) hash, (gpointer) blkinfo);
    }
    g_mutex_unlock(&lock);

    // Run the callback to check for end-of-interval
    qemu_plugin_register_vcpu_tb_exec_cb(tb, vcpu_tb_exec,
                                         QEMU_PLUGIN_CB_NO_REGS,
                                         (void *)blkinfo);

    // Bump the total and block exec counts. The order of registration
    // doesn't matter; inline operations run after callbacks.
    qemu_plugin_register_vcpu_tb_exec_inline(tb, QEMU_PLUGIN_INLINE_ADD_U64,
                                             &cur_insns, blkinfo->insns);
    qemu_plugin_register_vcpu_tb_exec_inline(tb, QEMU_PLUGIN_INLINE_ADD_U64,
                                             &blkinfo->exec_count, blkinfo->insns);
}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    if (info->system_emulation == true) {
        fprintf(stderr, "bbvgen: only support for user mode execution\n");
        return -1;
    }

    for (int i = 0; i < argc; i++) {
        char *opt = argv[i];
        g_autofree char **tokens = g_strsplit(opt, "=", 2);

        if (g_strcmp0(tokens[0], "bbv") == 0) {
            assert(strlen(tokens[1]) < sizeof(bbv_path));
            strncpy(bbv_path, tokens[1], sizeof(bbv_path));
        } else if (g_strcmp0(tokens[0], "bbvi") == 0) {
            assert(strlen(tokens[1]) < sizeof(bbvi_path));
            strncpy(bbvi_path, tokens[1], sizeof(bbvi_path));
        } else if (g_strcmp0(tokens[0], "ilen") == 0) {
            intv_length = strtoull(tokens[1], NULL, 0);
        } else if (g_strcmp0(tokens[0], "nblocks") == 0) {
            hot_count = strtoul(tokens[1], NULL, 0);
        } else {
            fprintf(stderr, "bbvgen: option parsing failed: %s\n", opt);
            return -1;
        }
    }

    outfile_init();

    if (bbv_file == Z_NULL && bbvi_file == Z_NULL) {
        fprintf(stderr, "bbvgen: at least one of {\"bbv=<path>\", \"bbvi=<path>\"} arguments must be supplied\n");
        return -1;
    }

    char *opt = getenv("QEMU_BBV_INTERVAL");
    if (opt != NULL) {
        intv_length = strtoull(opt, NULL, 0);
    }
    opt = getenv("QEMU_BBV_BLOCKS");
    if (opt != NULL) {
        hot_count = strtoul(opt, NULL, 0);
    }

    plugin_init(info->target_name);

    qemu_plugin_register_vcpu_syscall_ret_cb(id, vcpu_syscall_ret);
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
