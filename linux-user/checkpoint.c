/*
 * Copyright (c) 2021 by Rivos Inc.
 *
 * This work is licensed under the terms of the GNU GPL version 2.
 * See the COPYING file in the top-level directory.
 */

#include "checkpoint.h"

#define CKPT_FMT_VERSION 0x0001 /* version 0.1 */

static uint64_t interval_size = 0;
static uint64_t warmup_size = 0;
static unsigned long *stop_targets = NULL;
static unsigned int num_stop_targets = 0;
static const char *cptdir = "checkpoints";

#ifdef TARGET_CAN_CHECKPOINT
static void checkpoint_emit(CkptData *cd);
#endif

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

void checkpoint_set_dir(const char *arg)
{
    cptdir = strdup(arg);
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
    } else if (cd->in_workload) {
        // If we're not stopping, we still need a budget of >= 64K
        // because the icount_decr will still be doing its thing for
        // every block.
        // TODO: turn off ICOUNT and clear TB cache?
        cd->target_inst = 0;
        cs->icount_budget = 65536;
    } else {
        cs->tcg_cflags &= ~(CF_USE_ICOUNT);
        tb_flush(cs);
    }
}

static void checkpoint_setup(CPUState *cs, CkptData *cd) {
#ifdef TARGET_CAN_CHECKPOINT
    if (cd->stopping) {
        /* RIVOS-KW support the checkpoint flow */
        cs->tcg_cflags = CF_USE_ICOUNT;
        tb_flush(cs);
    }
#endif

    if (cd->stopping) {
        if (mkdir(cptdir, 0775) == -1) {
            perror("checkpoint mkdir");
            exit(EXIT_FAILURE);
        }
        cd->dir = open(cptdir, O_DIRECTORY);
    }
}

void checkpoint_init(CPUState *cs, CkptData *cd)
{
    cd->cs = cs;
    cd->total_instructions = 0;
    cd->stop_index = 0;
    cd->stopping = false;
    // TODO: we want this true at startup for some workloads like SPEC.
    cd->in_workload = false;
    // Clear the flag in case it was left on by a clone().
    cs->tcg_cflags &= ~CF_USE_ICOUNT;
    tb_flush(cs);

    if (!cd->in_workload) {
        return;
    }
    update_for_stop_index(cs, cd);

    checkpoint_setup(cs, cd);
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
    if (executed == 0 && cd->in_workload) {
#ifdef TARGET_CAN_CHECKPOINT
        checkpoint_emit(cd);
#endif

        cd->stop_index++;
        update_for_stop_index(cs, cd);
    } else {
        cs->icount_budget -= executed;
        if (cd->in_workload) {
            cd->total_instructions += executed;
        }
    }
}

void checkpoint_work_begin(CPUState *cs, CkptData *cd)
{
    cd->in_workload = true;
    update_for_stop_index(cs, cd);

    checkpoint_setup(cs, cd);
}

void checkpoint_work_end(CPUState *cs, CkptData *cd)
{
    cd->in_workload = false;
    cd->stopping = false;
}

#ifdef TARGET_CAN_CHECKPOINT

static int ckpt_vma_walker(void *priv, target_ulong start, target_ulong end,
                           unsigned long flags)
{
    CkptData *cd = (CkptData *)priv;
    const char *name = "heap";

    if (!(flags & PROT_READ)) {
        return 0;
    }

    CPUState *cs = cd->cs;
    TaskState *ts = cs->opaque;
    struct image_info *info = ts->info;
    if (start == info->stack_limit) {
        name = "stack";
    }

    uint64_t offset = cd->pos;
    if (offset > 0) {
        fprintf(cd->info, ",\n");
    }
    abi_ulong addr;
    for (addr = start; addr < end; addr += TARGET_PAGE_SIZE) {
        char page[TARGET_PAGE_SIZE];
        int error;

        error = copy_from_user(page, addr, sizeof (page));
        if (error != 0) {
            fprintf(stderr, "failed to read a page, " TARGET_FMT_lx "\n", addr);
            return -1;
        } else {
            fwrite(page, sizeof(page), 1, cd->pmem);
            cd->pos += sizeof(page);
        }
    }

    fprintf(cd->info,
            "        { \"vaddr\" : " TARGET_FMT_lu ", \"end\" : " TARGET_FMT_lu ", \"paddr\" : %" PRIu64 ", \"name\" : \"%s\" }",
            start, end, offset, name);
    return 0;
}

static void checkpoint_emit(CkptData *cd)
{
    int cdirfd, fd, dfd;
    char *dirname, *filename;
    DIR *d;
    struct dirent *dent;
    unsigned files = 0;

    //fprintf(stderr, "== checkpoint @ %" PRIu64 " ==\n", cd->target_inst);

    // Put this checkpoint's data in a new subdir of cd->dir
    dirname = g_strdup_printf("cpt.%ld", cd->target_inst);
    if (mkdirat(cd->dir, dirname, 0775) == -1) {
        perror("checkpoint subdir mkdir");
        exit(EXIT_FAILURE);
    }
    cdirfd = openat(cd->dir, dirname, O_DIRECTORY);
    if (cdirfd == -1) {
        perror("checkpoint subdir open");
        exit(EXIT_FAILURE);
    }
    g_free(dirname);

    // Start the JSON-formatted 'info' file
    filename = g_strdup_printf("qemu_%ld.json", cd->target_inst);
    fd = openat(cdirfd, filename, O_CREAT|O_TRUNC|O_WRONLY, 0664);
    if (fd == -1) {
        perror("checkpoint json open");
        exit(EXIT_FAILURE);
    }
    cd->info = fdopen(fd, "w");
    fprintf(cd->info, "{\n");
    g_free(filename);

    fprintf(cd->info, "    \"version\" : %u,\n", CKPT_FMT_VERSION);
    fprintf(cd->info,
            "    \"params\" : { \"interval\" : %lu, \"size\" : %lu, \"warmup\" : %lu },\n",
            stop_targets[cd->stop_index], interval_size, warmup_size);

    // Write out the physical memory and the VM region details
    filename = g_strdup_printf("qemu_%ld.pmem", cd->target_inst);
    fd = openat(cdirfd, filename, O_CREAT|O_TRUNC|O_WRONLY, 0664);
    if (fd == -1) {
        perror("checkpoint pmem open");
        exit(EXIT_FAILURE);
    }
    cd->pmem = fdopen(fd, "w");
    cd->pos = 0;
    fprintf(cd->info, "    \"pmem\" : \"%s\",\n", filename);
    fprintf(cd->info, "    \"regions\" : [\n");
    walk_memory_regions(cd, ckpt_vma_walker);
    fprintf(cd->info, "\n    ],\n");
    fclose(cd->pmem);
    g_free(filename);
    close(cdirfd);

    // For now, the target cpu routine will write to cd->info
    target_cpu_checkpoint(cd);

    // Since we can rely on Linux hosting, use the /proc filesystem to
    // identify the interesting file descriptors to checkpoint.
    d = opendir("/proc/self/fd");
    if (d == NULL) {
        perror("open /proc/self/fd");
        exit(EXIT_FAILURE);
    }
    dfd = dirfd(d);
    fprintf(cd->info, "    \"files\" : [\n");
    while ((dent = readdir(d)) != NULL) {
        if (dent->d_type == DT_LNK) {
            char buf[1024];
            ssize_t len = readlinkat(dfd, dent->d_name, buf, sizeof(buf));
            if (len == (ssize_t)-1) {
                fprintf(stderr, "ERROR: checkpoint failed to follow fd link %s\n", dent->d_name);
                exit(EXIT_FAILURE);
            }
            buf[len] = 0;
            if (!strncmp("/proc", buf, 5) || !strncmp("/dev", buf, 4)) {
                continue;
            }
            // Skip epoll fds and signalfds.
            if (!strncmp("anon_inode:[eventpoll]", buf, 22) ||
                !strncmp("anon_inode:[signalfd]", buf, 21)) {
                continue;
            }
            // Skip pipes and sockets for now.
            if (!strncmp("pipe:", buf, 5) || !strncmp("socket:", buf, 7)) {
                continue;
            }
            // skip the json fd and checkpoint dir fd
            unsigned long tgt_fd = strtoul(dent->d_name, NULL, 10);
            if (tgt_fd == fileno(cd->info) || tgt_fd == cd->dir) {
                continue;
            }
            // Regular files.
            int flags = fcntl(tgt_fd, F_GETFL, NULL);
            if (flags == -1) {
                fprintf(stderr, "ERROR: checkpoint failed to get flags for fd%lu\n", tgt_fd);
                exit(EXIT_FAILURE);
            }
            off_t pos = lseek(tgt_fd, 0, SEEK_CUR);
            if (pos == (off_t)-1) {
                fprintf(stderr, "ERROR: checkpoint failed on lseek() for fd%lu\n", tgt_fd);
                exit(EXIT_FAILURE);
            }
            struct stat st;
            if (fstat(tgt_fd, &st) == -1) {
                fprintf(stderr, "ERROR: checkpoint failed on stat() for fd%lu\n", tgt_fd);
                exit(EXIT_FAILURE);
            }
            if (files++) {
                fprintf(cd->info, ",\n");
            }
            fprintf(cd->info,
                    "        { \"fd\" : %lu, \"path\" : \"%s\", \"pos\" : %lu, \"flags\" : %u, \"mode\" : %u }",
                    tgt_fd, buf, pos, flags, st.st_mode & 0777);
        }
    }
    if (files) {
        fprintf(cd->info, "\n");
    }
    fprintf(cd->info, "    ]\n");
    closedir(d);

    fprintf(cd->info, "}\n");
    fclose(cd->info);
}

#endif
