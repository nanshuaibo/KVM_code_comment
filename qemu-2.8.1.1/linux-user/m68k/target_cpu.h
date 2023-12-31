/*
 * m68k specific CPU ABI and functions for linux-user
 *
 * Copyright (c) 2005-2007 CodeSourcery
 * Written by Paul Brook
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef M68K_TARGET_CPU_H
#define M68K_TARGET_CPU_H

static inline void cpu_clone_regs(CPUM68KState *env, target_ulong newsp)
{
    if (newsp) {
        env->aregs[7] = newsp;
    }
    env->dregs[0] = 0;
}

static inline void cpu_set_tls(CPUM68KState *env, target_ulong newtls)
{
    CPUState *cs = CPU(m68k_env_get_cpu(env));
    TaskState *ts = cs->opaque;

    ts->tp_value = newtls;
}

#endif
