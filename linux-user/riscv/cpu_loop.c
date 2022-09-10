/*
 *  qemu user cpu loop
 *
 *  Copyright (c) 2003-2008 Fabrice Bellard
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu.h"
#include "user-internals.h"
#include "checkpoint.h"
#include "cpu_loop-common.h"
#include "signal-common.h"
#include "elf.h"
#include "loader.h"
#include "user-mmap.h"
#include "semihosting/common-semi.h"

#ifdef CONFIG_M5
#include <gem5/m5ops.h>
#endif

void cpu_loop(CPURISCVState *env)
{
    CPUState *cs = env_cpu(env);
    RISCVCPU *riscv_cpu = RISCV_CPU(cs);
    int trapnr;
    target_ulong ret;
    CkptData ckpt;

    checkpoint_init(cs, &ckpt);

    /* If m5ops were not enabled, but checkpointing is, then consider the
       entire process as the region of interest. */
    if (!riscv_cpu->cfg.ext_XM5Ops) {
        checkpoint_work_begin(cs, &ckpt);
    }

    for (;;) {
        checkpoint_before_exec(&ckpt);

        cpu_exec_start(cs);
        trapnr = cpu_exec(cs);
        cpu_exec_end(cs);
        process_queued_cpu_work(cs);

        checkpoint_after_exec(&ckpt);

        switch (trapnr) {
        case EXCP_INTERRUPT:
            /* just indicate that signals should be handled asap */
            break;
        case EXCP_ATOMIC:
            cpu_exec_step_atomic(cs);
            break;
        case RISCV_EXCP_U_ECALL:
            env->pc += 4;
            if (env->gpr[xA7] == TARGET_NR_arch_specific_syscall + 15) {
                /* riscv_flush_icache_syscall is a no-op in QEMU as
                   self-modifying code is automatically detected */
                ret = 0;
            } else {
                ret = do_syscall(env,
                                 env->gpr[(env->elf_flags & EF_RISCV_RVE)
                                    ? xT0 : xA7],
                                 env->gpr[xA0],
                                 env->gpr[xA1],
                                 env->gpr[xA2],
                                 env->gpr[xA3],
                                 env->gpr[xA4],
                                 env->gpr[xA5],
                                 0, 0);
            }
            if (ret == -QEMU_ERESTARTSYS) {
                env->pc -= 4;
            } else if (ret != -QEMU_ESIGRETURN) {
                env->gpr[xA0] = ret;
            }
            if (cs->singlestep_enabled) {
                goto gdbstep;
            }
            break;
        case RISCV_EXCP_ILLEGAL_INST:
            force_sig_fault(TARGET_SIGILL, TARGET_ILL_ILLOPC, env->pc);
            break;
        case RISCV_EXCP_BREAKPOINT:
        case EXCP_DEBUG:
        gdbstep:
            force_sig_fault(TARGET_SIGTRAP, TARGET_TRAP_BRKPT, env->pc);
            break;
        case RISCV_EXCP_SEMIHOST:
            do_common_semihosting(cs);
            env->pc += 4;
            break;
#ifdef CONFIG_M5
        case EXCP_M5OP:
	    {
                uint32_t m5op, m5op_num;
                get_user_u32(m5op, env->pc);
                m5op_num = (m5op >> 25);
                if (m5op_num == M5OP_WORK_BEGIN) {
                    checkpoint_work_begin(cs, &ckpt);
                } else if (m5op_num == M5OP_WORK_END) {
                    checkpoint_work_end(cs, &ckpt);
                } else if (m5op_num == M5OP_CHECKPOINT) {
                    EXCP_DUMP(env, "\nqemu: m5op checkpoint unimplemented - aborting\n");
                    exit(EXIT_FAILURE);
                }
                qemu_plugin_vcpu_m5op_cb(cs, m5op_num);
                // HACK: assume any m5op plugin callbacks will require flushing all TBs.
                tb_flush(cs);
                qemu_plugin_flush_cb();
                env->pc += 4;
                break;
	    }
#endif // CONFIG_M5
        default:
            EXCP_DUMP(env, "\nqemu: unhandled CPU exception %#x - aborting\n",
                     trapnr);
            exit(EXIT_FAILURE);
        }

        process_pending_signals(env);
    }
}

void target_cpu_copy_regs(CPUArchState *env, struct target_pt_regs *regs)
{
    CPUState *cpu = env_cpu(env);
    TaskState *ts = cpu->opaque;
    struct image_info *info = ts->info;

    env->pc = regs->sepc;
    env->gpr[xSP] = regs->sp;
    env->elf_flags = info->elf_flags;

    if ((env->misa_ext & RVE) && !(env->elf_flags & EF_RISCV_RVE)) {
        error_report("Incompatible ELF: RVE cpu requires RVE ABI binary");
        exit(EXIT_FAILURE);
    }

    ts->stack_base = info->start_stack;
    ts->heap_base = info->brk;
    /* This will be filled in on the first SYS_HEAPINFO call.  */
    ts->heap_limit = 0;
}

void target_cpu_checkpoint(CkptData *cd)
{
    CPUState *cs = cd->cs;
    CPUArchState *env = cs->env_ptr;
    TaskState *ts = cs->opaque;
    struct image_info *info = ts->info;

    fprintf(cd->info, "    \"cpu\" : {\n");
    fprintf(cd->info, "        \"instructions\" : %lu,\n", cd->total_instructions);
    fprintf(cd->info, "        \"pc\" : " TARGET_FMT_lu ",\n", env->pc);
    fprintf(cd->info, "        \"brk\" : " TARGET_FMT_lu ",\n", do_brk(0));
    fprintf(cd->info, "        \"mmap\" : " TARGET_FMT_lu ",\n", mmap_next_start);
    fprintf(cd->info, "        \"stack\" : { \"start\" : " TARGET_FMT_lu ", \"end\" : %lu },\n",
            info->stack_limit, info->stack_limit+guest_stack_size-1);
    fprintf(cd->info, "        \"gprs\" : [");
    for (unsigned gpr = 0; gpr < 32; gpr++) {
        fprintf(cd->info, " " TARGET_FMT_lu "%s", env->gpr[gpr], gpr+1 == 32 ? "" : ",");
    }
    fprintf(cd->info, " ],\n");
    fprintf(cd->info, "        \"fprs\" : [");
    for (unsigned fpr = 0; fpr < 32; fpr++) {
        fprintf(cd->info, " %lu%s", env->fpr[fpr], fpr+1 == 32 ? "" : ",");
    }
    fprintf(cd->info, " ],\n");
    // TODO: vector registers
    fprintf(cd->info, "        \"vrs\" : [");
    fprintf(cd->info, " ]\n");
    // TODO: add any CSRs that become necessary for user-mode checkpoints
    fprintf(cd->info, "    },\n");
}
