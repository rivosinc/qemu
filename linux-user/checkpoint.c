/*
 * Copyright (c) 2021 by Rivos Inc.
 *
 * This work is licensed under the terms of the GNU GPL version 2.
 * See the COPYING file in the top-level directory.
 */

#include "checkpoint.h"

#include "qemu.h"
#include "user-internals.h"

static uint64_t interval_size = 0;
static uint64_t warmup_size = 0;
static unsigned long *stop_targets = NULL;
static unsigned int num_stop_targets = 0;

bool checkpoint_opt_parse(const char *arg)
{
    // Peel off the interval size and warmup length first; count the
    // number of intervals and build a list (scaling by the interval
    // size and subtracting the warmup).
    char *list, *p;
    errno = 0;
    interval_size = strtoull(arg, &list, 0);
    unsigned count = 0;
    if (errno != 0 || list == arg || *list != ',') {
        return false;
    }
    p = ++list;
    warmup_size = strtoull(p, &list, 0);
    if (errno != 0 || list == p || *list != ',') {
        return false;
    }
    p = list;
    while (p != NULL) {
        p++;
        if (*p == ',' || *p == '\0') {
            return false;
        }
        count++;
        p = strchr(p, ',');
    }
    if (count == 0) {
        return false;
    }
    num_stop_targets = count;
    stop_targets = g_malloc(num_stop_targets * sizeof(unsigned long));
    p = list;
    count = 0;
    errno = 0;
    while (p != NULL && *p == ',') {
        p++;
        stop_targets[count] = strtoul(p, &p, 0);
        if (errno != 0) {
            g_free(stop_targets);
            num_stop_targets = 0;
            return false;
        }
        count++;
    }

    return true;
}

static void update_for_stop_index(CPUState *cs, CkptData *cd)
{
    cd->stopping = cd->stop_index < num_stop_targets;
    if (cd->stopping) {
        uint64_t target_inst = stop_targets[cd->stop_index] * interval_size;
        if (target_inst < warmup_size) {
            target_inst = 0;
        } else {
            target_inst = target_inst - warmup_size;
        }
        cd->target_inst = target_inst;
        cs->icount_budget = cd->target_inst - cd->total_instructions;
    } else {
        // If we're not stopping, we still need a budget of >= 64K
        // because the icount_decr will still be doing its thing for
        // every block.
        // TODO: turn off ICOUNT and clear TB cache?
        cd->target_inst = 0;
        cs->icount_budget = 65536;
    }
}

void checkpoint_init(CPUState *cs, CkptData *cd)
{
    cd->cs = cs;
    cd->total_instructions = 0;
    cd->stop_index = 0;

    update_for_stop_index(cs, cd);

#ifdef TARGET_CAN_CHECKPOINT
    if (cd->stopping) {
        /* RIVOS-KW support the checkpoint flow */
        cs->tcg_cflags = CF_USE_ICOUNT;
    }
#endif
}

void checkpoint_before_exec(CkptData *cd)
{
    CPUState *cs = cd->cs;

    // Constrain to low u16 "icount_prepare_for_run()"
    //printf("Start budget %lu\n", cs->icount_budget);
    uint16_t insns_left = MIN(0xffff, cs->icount_budget);
    cpu_neg(cs)->icount_decr.u16.low = insns_left;
    cs->icount_extra = cs->icount_budget - insns_left;
}

void checkpoint_after_exec(CkptData *cd)
{
    if (!cd->stopping) {
        return;
    }

    CPUState *cs = cd->cs;

    // Update the budget based on what got executed "icount_update()"
    //printf("Back to loop %lu %d %ld\n", cs->icount_budget, cpu_neg(cs)->icount_decr.u16.low, cs->icount_extra);
    uint64_t executed = (cs->icount_budget - (cpu_neg(cs)->icount_decr.u16.low + cs->icount_extra));
    if (executed == 0) {
        fprintf(stderr, "== checkpoint @ %" PRIu64 " ==\n", cd->target_inst);
        cd->stop_index++;
        update_for_stop_index(cs, cd);
    } else {
        cs->icount_budget -= executed;
        cd->total_instructions += executed;
    }
}
