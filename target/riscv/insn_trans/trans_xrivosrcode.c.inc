/*
 * RISC-V translation routines for Rivos Rcode instructions
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

/*
 * Since Rcode instructions are in their own decode table that is only
 * searched after checking the existence of the Rcode extension, no
 * checks are needed within the translation functions.
 */

static bool trans_rret(DisasContext *ctx, arg_rret *a)
{
#ifndef CONFIG_USER_ONLY
    gen_helper_rret(cpu_pc, cpu_env);
    tcg_gen_exit_tb(NULL, 0); /* no chaining */
    ctx->base.is_jmp = DISAS_NORETURN;
    return true;
#else
    return false;
#endif
}

static bool gen_rload_tl(DisasContext *ctx, arg_rlb *a, MemOp memop)
{
    TCGv dest = dest_gpr(ctx, a->rd);
    TCGv addr = get_address(ctx, a->rs1, a->imm);

    tcg_gen_qemu_ld_tl(dest, addr, MMU_RCODE_IDX, memop);
    gen_set_gpr(ctx, a->rd, dest);
    return true;
}

static bool trans_rlb(DisasContext *ctx, arg_rlb *a)
{
    return gen_rload_tl(ctx, a, MO_SB);
}

static bool trans_rlh(DisasContext *ctx, arg_rlh *a)
{
    return gen_rload_tl(ctx, a, MO_TESW);
}

static bool trans_rlw(DisasContext *ctx, arg_rlw *a)
{
    return gen_rload_tl(ctx, a, MO_TESL);
}

static bool trans_rld(DisasContext *ctx, arg_rld *a)
{
    return gen_rload_tl(ctx, a, MO_TESQ);
}

static bool trans_rlbu(DisasContext *ctx, arg_rlbu *a)
{
    return gen_rload_tl(ctx, a, MO_UB);
}

static bool trans_rlhu(DisasContext *ctx, arg_rlhu *a)
{
    return gen_rload_tl(ctx, a, MO_TEUW);
}

static bool trans_rlwu(DisasContext *ctx, arg_rlwu *a)
{
    return gen_rload_tl(ctx, a, MO_TEUL);
}

static bool gen_rstore_tl(DisasContext *ctx, arg_rsb *a, MemOp memop)
{
    TCGv addr = get_address(ctx, a->rs1, a->imm);
    TCGv data = get_gpr(ctx, a->rs2, EXT_NONE);

    tcg_gen_qemu_st_tl(data, addr, MMU_RCODE_IDX, memop);
    return true;
}

static bool trans_rsb(DisasContext *ctx, arg_rsb *a)
{
    return gen_rstore_tl(ctx, a, MO_SB);
}

static bool trans_rsh(DisasContext *ctx, arg_rsh *a)
{
    return gen_rstore_tl(ctx, a, MO_TEUW);
}

static bool trans_rsw(DisasContext *ctx, arg_rsw *a)
{
    return gen_rstore_tl(ctx, a, MO_TEUL);
}

static bool trans_rsd(DisasContext *ctx, arg_rsd *a)
{
    return gen_rstore_tl(ctx, a, MO_TEUQ);
}

static bool trans_rinval_mtt(DisasContext *ctx, arg_rinval_mtt *a)
{
#ifndef CONFIG_USER_ONLY
    // Conservative flushing for now - ignore page in rs1
    gen_helper_tlb_flush(cpu_env);
    return true;
#endif
    return false;
}

