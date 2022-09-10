/*
 * RISC-V translation routines for the XVentanaCondOps extension.
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

static bool trans_m5_arm(DisasContext *ctx, arg_m5_arm *a)
{
    generate_exception(ctx, EXCP_M5OP);
    return true;
}

static bool trans_m5_quiesce(DisasContext *ctx, arg_m5_quiesce *a)
{
    generate_exception(ctx, EXCP_M5OP);
    return true;
}

static bool trans_m5_quiesce_ns(DisasContext *ctx, arg_m5_quiesce_ns *a)
{
    generate_exception(ctx, EXCP_M5OP);
    return true;
}

static bool trans_m5_quiesce_cycle(DisasContext *ctx, arg_m5_quiesce_cycle *a)
{
    generate_exception(ctx, EXCP_M5OP);
    return true;
}

static bool trans_m5_quiesce_time(DisasContext *ctx, arg_m5_quiesce_time *a)
{
    generate_exception(ctx, EXCP_M5OP);
    return true;
}

static bool trans_m5_rpns(DisasContext *ctx, arg_m5_rpns *a)
{
    generate_exception(ctx, EXCP_M5OP);
    return true;
}

static bool trans_m5_wake_cpu(DisasContext *ctx, arg_m5_wake_cpu *a)
{
    generate_exception(ctx, EXCP_M5OP);
    return true;
}

static bool trans_m5_exit(DisasContext *ctx, arg_m5_exit *a)
{
    generate_exception(ctx, EXCP_M5OP);
    return true;
}

static bool trans_m5_fail(DisasContext *ctx, arg_m5_fail *a)
{
    generate_exception(ctx, EXCP_M5OP);
    return true;
}

static bool trans_m5_sum(DisasContext *ctx, arg_m5_sum *a)
{
    generate_exception(ctx, EXCP_M5OP);
    return true;
}

static bool trans_m5_init_param(DisasContext *ctx, arg_m5_init_param *a)
{
    generate_exception(ctx, EXCP_M5OP);
    return true;
}

static bool trans_m5_load_symbol(DisasContext *ctx, arg_m5_load_symbol *a)
{
    generate_exception(ctx, EXCP_M5OP);
    return true;
}

static bool trans_m5_reset_stats(DisasContext *ctx, arg_m5_reset_stats *a)
{
    generate_exception(ctx, EXCP_M5OP);
    return true;
}

static bool trans_m5_dump_stats(DisasContext *ctx, arg_m5_dump_stats *a)
{
    generate_exception(ctx, EXCP_M5OP);
    return true;
}

static bool trans_m5_dump_reset_stats(DisasContext *ctx, arg_m5_dump_reset_stats *a)
{
    generate_exception(ctx, EXCP_M5OP);
    return true;
}

static bool trans_m5_checkpoint(DisasContext *ctx, arg_m5_checkpoint *a)
{
    generate_exception(ctx, EXCP_M5OP);
    return true;
}

static bool trans_m5_write_file(DisasContext *ctx, arg_m5_write_file *a)
{
    generate_exception(ctx, EXCP_M5OP);
    return true;
}

static bool trans_m5_read_file(DisasContext *ctx, arg_m5_read_file *a)
{
    generate_exception(ctx, EXCP_M5OP);
    return true;
}

static bool trans_m5_debug_break(DisasContext *ctx, arg_m5_debug_break *a)
{
    generate_exception(ctx, EXCP_M5OP);
    return true;
}

static bool trans_m5_switch_cpu(DisasContext *ctx, arg_m5_switch_cpu *a)
{
    generate_exception(ctx, EXCP_M5OP);
    return true;
}

static bool trans_m5_add_symbol(DisasContext *ctx, arg_m5_add_symbol *a)
{
    generate_exception(ctx, EXCP_M5OP);
    return true;
}

static bool trans_m5_panic(DisasContext *ctx, arg_m5_panic *a)
{
    generate_exception(ctx, EXCP_M5OP);
    return true;
}

static bool trans_m5_reserved1(DisasContext *ctx, arg_m5_reserved1 *a)
{
    generate_exception(ctx, EXCP_M5OP);
    return true;
}

static bool trans_m5_reserved2(DisasContext *ctx, arg_m5_reserved2 *a)
{
    generate_exception(ctx, EXCP_M5OP);
    return true;
}

static bool trans_m5_reserved3(DisasContext *ctx, arg_m5_reserved3 *a)
{
    generate_exception(ctx, EXCP_M5OP);
    return true;
}

static bool trans_m5_reserved4(DisasContext *ctx, arg_m5_reserved4 *a)
{
    generate_exception(ctx, EXCP_M5OP);
    return true;
}

static bool trans_m5_reserved5(DisasContext *ctx, arg_m5_reserved5 *a)
{
    generate_exception(ctx, EXCP_M5OP);
    return true;
}

static bool trans_m5_work_begin(DisasContext *ctx, arg_m5_work_begin *a)
{
    generate_exception(ctx, EXCP_M5OP);
    return true;
}

static bool trans_m5_work_end(DisasContext *ctx, arg_m5_work_end *a)
{
    generate_exception(ctx, EXCP_M5OP);
    return true;
}

static bool trans_m5_dist_toggle_sync(DisasContext *ctx, arg_m5_dist_toggle_sync *a)
{
    generate_exception(ctx, EXCP_M5OP);
    return true;
}

static bool trans_m5_workload(DisasContext *ctx, arg_m5_workload *a)
{
    generate_exception(ctx, EXCP_M5OP);
    return true;
}
