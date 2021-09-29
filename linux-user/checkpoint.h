/*
 * Copyright (c) 2021 by Rivos Inc.
 *
 * This work is licensed under the terms of the GNU GPL version 2.
 * See the COPYING file in the top-level directory.
 */

#ifndef LINUX_USER_CHECKPOINT_H
#define LINUX_USER_CHECKPOINT_H

#include "qemu/osdep.h"

typedef struct CkptData {
    uint64_t total_instructions;
    uint64_t target_inst;
    uint32_t stop_index;
    bool stopping;
    CPUState *cs;
} CkptData;

bool checkpoint_opt_parse(const char *arg);
void checkpoint_init(CPUState *cs, CkptData *cd);
void checkpoint_before_exec(CkptData *cd);
void checkpoint_after_exec(CkptData *cd);

#endif
