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

static gzFile bbv_file = Z_NULL;
static gzFile bbvi_file = Z_NULL;
static bool do_fetch_stats = false;

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

typedef struct {
    uint64_t id;
    uint64_t start_addr;
    uint64_t last_pc;
    uint64_t exec_count;
    uint64_t total_count;
    uint32_t insns;
    uint32_t bytes;
    uint16_t *off_to_inst;
} BlockInfo;

// Taken-branch detection requires some information on the previous
// translation block.
static BlockInfo *prev_block = NULL;

// Storage for branch distance histogram
static uint64_t deltas[64] = {};

enum { FETCH_64B, FETCH_2x32B, NUM_FETCH_ALGO };

// Buckets need to cover 1/2/../33 instructions and 2/4/../66 bytes,
// because of the case where a 4B instruction falls at byte 62.
#define BUCKETS 33

struct fetch_info {
    uint64_t total;
    uint32_t insts;
    uint32_t bytes;
    uint64_t inst_buckets[BUCKETS];
    uint64_t bytes_buckets[BUCKETS];
    bool one_taken;
    uint8_t  kind;
};
static struct fetch_info finfos[NUM_FETCH_ALGO];

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

static void filter_block_final(gpointer key,
                               gpointer value,
                               gpointer user_data)
{
    GList **blocks = (GList **)user_data;
    BlockInfo *cnt = (BlockInfo *) value;
    // Move the total_count into exec_count, so the final top blocks
    // summary can reuse cmp_exec_count and emit_hot_blocks.
    cnt->exec_count = cnt->total_count;
    if (cnt->exec_count > 0) {
        *blocks = g_list_prepend(*blocks, value);
    }
}

static void latch_count(gpointer data,
                        gpointer user_data)
{
    BlockInfo *cnt = (BlockInfo *) data;
    // Accumulate the total count for the final summary; reset the
    // exec count for the next interval.
    cnt->total_count += cnt->exec_count;
    cnt->exec_count = 0;
}

static void emit_hot_blocks(GList *blocks, unsigned count, uint64_t region_count, unsigned indent)
{
    GList *it = blocks;
    for (unsigned i = 0; (i < count) && it; i++, it = it->next) {
        BlockInfo *block = (BlockInfo *)it->data;
        if (i > 0) {
            gzprintf(bbvi_file, ",\n");
        }
        gzprintf(bbvi_file, "%*s{\"pc\" : %"PRIu64", \"len\" : %lu, \"icount\" : %"PRIu64", \"pct\": %.2f }",
                 indent, " ", block->start_addr, block->insns, block->exec_count,
                 (float)block->exec_count*100 / region_count);
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
}

static void emit_fetch_stats_array(struct fetch_info *info, bool insts, unsigned indent, bool more)
{
    gzprintf(bbvi_file, "%*s\"%s-distr\" : [\n", indent, " ", insts ? "inst" : "bytes");
    for (unsigned i = 0; i < BUCKETS; i++) {
        const bool last = (i == BUCKETS-1);
        if (insts) {
            gzprintf(bbvi_file, "%*s{ \"value\" : %u, \"count\" : %" PRIu64 ", \"pct\" : %.2f }%s\n",
                     indent+4, " ", i+1, info->inst_buckets[i], last ? "" : ",",
                     100.0 * (double)info->inst_buckets[i]/info->total);
        } else {
            gzprintf(bbvi_file, "%*s{ \"value\" : %u, \"count\" : %" PRIu64 ", \"pct\" : %.2f }%s\n",
                     indent+4, " ", (i+1) * 2, info->bytes_buckets[i], last ? "" : ",",
                     100.0 * (double)info->bytes_buckets[i]/info->total);
        }
    }
    gzprintf(bbvi_file, "%*s]%s\n", indent, " ", more ? "," : "");
}

static void emit_fetch_stats(struct fetch_info *info, unsigned indent, bool more)
{
    gzprintf(bbvi_file, "%*s\"%s\" : {\n", indent, " ", info->kind == FETCH_64B ? "64B" : "2x32B");
    gzprintf(bbvi_file, "%*s\"count\" : %" PRIu64 ",\n", indent+4, " ", info->total);
    emit_fetch_stats_array(info, true, indent+4, true);
    emit_fetch_stats_array(info, false, indent+4, false);
    gzprintf(bbvi_file, "%*s}%s\n", indent, " ", more ? "," : "");
}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    end_interval();
    total_insns += cur_insns;
    gzclose_w(bbv_file);

    if (bbvi_file != Z_NULL) {
        gzprintf(bbvi_file, "\n    ],\n");
        gzprintf(bbvi_file, "    \"instructions\" : %"PRIu64",\n", total_insns);

        // Pull the top blocks from the entire run and emit_hot_blocks
        GList *blocks = NULL;
        g_hash_table_foreach(allblocks, filter_block_final, (gpointer)&blocks);
        blocks = g_list_sort(blocks, cmp_exec_count);
        gzprintf(bbvi_file, "    \"blocks\" : [\n");
        emit_hot_blocks(blocks, hot_count, total_insns, 8);
        bool more = do_fetch_stats;
        gzprintf(bbvi_file, "    ]%s\n", more ? "," : "");
        g_list_free(blocks);

        if (do_fetch_stats) {
            uint64_t takens = 0;
            for (unsigned i =0; i<64; i++) {
                takens += deltas[i];
            }
            gzprintf(bbvi_file, "    \"taken-branches\" : {\n");
            gzprintf(bbvi_file, "        \"count\" : %" PRIu64 ",\n", takens);
            gzprintf(bbvi_file, "        \"target-distances\" : [\n");
            uint64_t cumulative = 0;
            for (unsigned i = 0; i<64; i++) {
                cumulative += deltas[i];
                if (i >= 12) {
                    gzprintf(bbvi_file, "            { \"common-bits\" : %u, \"cumulative\": %" PRIu64 ", \"pct\": %.2f }%s\n",
                             i, cumulative, 100.0 * (float)cumulative/takens, cumulative == takens ? "" : ",");
                }
                if (cumulative == takens) {
                    break;
                }
            }
            gzprintf(bbvi_file, "        ]\n");
            gzprintf(bbvi_file, "    }%s\n", more ? "," : "");
            more = true;        /* fetch stats follow the taken details */

            gzprintf(bbvi_file, "    \"fetch-stats\" : {\n");
            for (unsigned i = 0; i < NUM_FETCH_ALGO; i++) {
                emit_fetch_stats(&finfos[i], 8, i+1<NUM_FETCH_ALGO);
            }
            more = false;       /* nothing after these fetch stats */
            gzprintf(bbvi_file, "    }%s\n", more ? "," : "");
        }

        gzprintf(bbvi_file, "}\n");
        gzclose_w(bbvi_file);
    }
}

static void plugin_init(void)
{
    allblocks = g_hash_table_new(NULL, g_direct_equal);
    gzprintf(bbvi_file, "{\n    \"source\" : \"qemu-bbvgen\",\n");
    gzprintf(bbvi_file, "    \"intervals\" : [\n");
}

static void log_fetch_run(struct fetch_info *info)
{
    g_assert(info->insts > 0 && info->bytes > 0);
    g_assert(info->insts <= BUCKETS && info->bytes/2 <= BUCKETS);
    info->total++;
    info->inst_buckets[info->insts-1]++;
    info->bytes_buckets[info->bytes/2-1]++;
    //printf("  LOG%u: %u %u\n", info->kind, info->insts, info->bytes);
    g_assert((info->kind != FETCH_2x32B) || (info->insts > 1));
    info->bytes = 0;
    info->insts = 0;
    info->one_taken = false;
}

// Not concerned with taken or not taken here; just do as many fetches
// as it takes to get through the end of the given block.
static void fetch_loop(struct fetch_info *info, BlockInfo *bb)
{
    unsigned left = bb->bytes;
    unsigned space = 64 - info->bytes;
    unsigned taken_insts = 0;   /* remember how many insts consumed */
    unsigned index = 0;         /* track position in off_to_inst[] */

    while (left) {
        // Take as much as possible as we repeat the loop body
        unsigned take = left < space ? left : space;
        index += take/2 - 1;
        // Deal with straddle case: pull the extra 2B in the fetch
        if (bb->off_to_inst[index] == 0) {
            index++;
            take += 2;
            g_assert(bb->off_to_inst[index] > 0);
        }
        const unsigned new_insts = bb->off_to_inst[index] - taken_insts;
        //printf(" TAKE%u %u %u @ %u\n", info->kind, new_insts, take, bb->off_to_inst[index]);
        info->insts += new_insts;
        info->bytes += take;
        // Update the progress trackers
        taken_insts = bb->off_to_inst[index];
        index++;
        // If the fetch buffer is full, log the fetch. It's possible
        // the fetch happened to terminate with a taken branch, but we
        // don't know that here.
        if (info->bytes >= 64) {
            log_fetch_run(info);
            space = 64;
        }
        // Paranoia - sanity-check the math
        g_assert(take <= left);
        left -= take;
        //printf(" LEFT%u -> %u\n", kind, left);
    }
}

static void vcpu_tb_exec(unsigned int cpu_index, void *udata)
{
    BlockInfo *cnt = NULL;
    const uint64_t hash = (uint64_t) udata;

    // If we're looking for taken branches, we need info from the
    // previous basic block, and have to look up this one. Since this
    // is significant extra work, we don't want to do it unless the
    // user asked.
    if (do_fetch_stats) {
        cnt = (BlockInfo *) g_hash_table_lookup(allblocks, (gconstpointer) hash);
        //printf("Block @ %012" PRIx64 "\n", cnt->start_addr);

        // First determine if the block we're about to execute is at
        // the target of a taken branch. This affects all the fetch
        // stats collection.
        bool taken = false;

        if (prev_block) {
            const uint64_t target_pc = hash;
            const uint64_t fallthrough_pc = prev_block->start_addr + prev_block->bytes;
            taken = (target_pc != fallthrough_pc);
            if (taken) {
                const uint64_t branch_pc = prev_block->last_pc;
                const uint64_t xor = branch_pc ^ target_pc;
                const unsigned bits = 64-__builtin_clzl(xor);
                //printf("  %012" PRIx64 " -> %012" PRIx64 " [%012" PRIx64 "/ %2u]\n",
                //       branch_pc, target_pc, xor, bits);
                deltas[bits]++;
            }
        }

        prev_block = cnt;

        // If the previous block ended with a taken branch, we may
        // need to log that fetch group and start a new one.
        if (taken) {
            struct fetch_info *info = &finfos[FETCH_64B];
            // It's possible that looping through the previous block
            // just happened to already log/flush a taken branch at
            // the block's end; in that case, we ignore the taken
            // branch here.
            if (info->insts) {
                log_fetch_run(info);
            }

            // This taken closes the 2x32 fetch group if either it's
            // the second (one_taken == true) or it's the first and it
            // occurs at 32B or later.
            info = &finfos[FETCH_2x32B];
            if (info->one_taken || info->bytes >= 32) {
                log_fetch_run(info);
            } else if (info->insts) {
                // If the fetch group is still going, note that we
                // have seen the first taken branch.
                info->one_taken = true;
            }
        }

        // Now consume the rest of this block, logging each completed
        // fetch group.
        //printf(" -LOOP-\n");
        for (unsigned i = 0; i < NUM_FETCH_ALGO; i++) {
            fetch_loop(&finfos[i], cnt);
        }
    }

    // The callback has to run for every TB execution so we can detect
    // the end of an interval. Most of the time we just bail
    // immediately. Note that inline operations (counter increment)
    // run after callbacks.
    if (cur_insns + drift < intv_length) {
      return;
    }

    end_interval();

    if (cnt == NULL) {
        cnt = (BlockInfo *) g_hash_table_lookup(allblocks, (gconstpointer) hash);
    }
    // Remember the PC that started each interval
    intv_start_pc = cnt->start_addr;

    // Track drift due to ending intervals on block boundaries. We
    // want interval starts to stay close to (intv_num * intv_length).
    drift = (cur_insns + drift) - intv_length;

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
    const uint64_t hash = pc;

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
      if (do_fetch_stats) {
          size_t n = qemu_plugin_tb_n_insns(tb);
          size_t bytes = 0;
          // Since blocks can be of arbitrary size, dynamically
          // allocate the off_to_inst array. Have to iterate the
          // instructions to get the byte size of the block.
          for (size_t i = 0; i < n; i++) {
              struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
              cnt->last_pc = pc + bytes;
              bytes += qemu_plugin_insn_size(insn);
          }
          cnt->off_to_inst = g_new0(uint16_t, bytes/2);
          // Log each instruction start in the offset array. A zero at
          // any index means (index+1)*2 bytes is in the middle of an
          // instruction. A non-zero value means that many
          // instructions are included in the first (index+1)*2 bytes
          // of the block.
          for (size_t i = 0; i < n; i++) {
              struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
              cnt->bytes += qemu_plugin_insn_size(insn);
              cnt->off_to_inst[cnt->bytes/2-1] = i+1;
          }
      }
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
    for (int i = 0; i < argc; i++) {
        char *opt = argv[i];
        g_autofree char **tokens = g_strsplit(opt, "=", 2);

        if (g_strcmp0(tokens[0], "bbv") == 0) {
            bbv_file = gzopen(tokens[1], "wb9");
            if (bbv_file == Z_NULL) {
                return -1;
            }
        } else if (g_strcmp0(tokens[0], "bbvi") == 0) {
            bbvi_file = gzopen(tokens[1], "wb9");
            if (bbvi_file == Z_NULL) {
                return -1;
            }
        } else if (g_strcmp0(tokens[0], "fetch") == 0) {
            if (!qemu_plugin_bool_parse(tokens[0], tokens[1], &do_fetch_stats)) {
                fprintf(stderr, "bbvgen: boolean argument parsing failed: %s\n", opt);
                return -1;
            }
        } else {
            fprintf(stderr, "bbvgen: option parsing failed: %s\n", opt);
            return -1;
        }
    }

    if (do_fetch_stats) {
        for (unsigned i = 0; i < NUM_FETCH_ALGO; i++) {
            finfos[i].kind = i;
        }
    }

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

    plugin_init();

    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
