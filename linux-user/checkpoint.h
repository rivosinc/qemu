/*
 * Copyright (c) 2021 by Rivos Inc.
 *
 * This work is licensed under the terms of the GNU GPL version 2.
 * See the COPYING file in the top-level directory.
 */

#ifndef LINUX_USER_CHECKPOINT_H
#define LINUX_USER_CHECKPOINT_H

#include "qemu/osdep.h"
#include "qemu.h"
#include "user-internals.h"

typedef struct CkptData {
    uint64_t total_instructions;
    uint64_t target_inst;
    uint32_t stop_index;
    bool stopping;
    bool in_workload;
    CPUState *cs;
    int dir;
    FILE *pmem;
    FILE *info;
    uint64_t pos;
} CkptData;

bool checkpoint_opt_parse(const char *arg);
void checkpoint_set_dir(const char *arg);

void checkpoint_init(CPUState *cs, CkptData *cd);
void checkpoint_before_exec(CkptData *cd);
void checkpoint_after_exec(CkptData *cd);
void checkpoint_work_begin(CPUState *cs, CkptData *cd);
void checkpoint_work_end(CPUState *cs, CkptData *cd);

#ifdef TARGET_CAN_CHECKPOINT
extern void target_cpu_checkpoint(CkptData *cd);
#endif

#endif
