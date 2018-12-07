/* Copyright (C) 2018 Intel Corporation
                      Isaku Yamahata <isaku.yamahata at gmail.com>
                                     <isaku.yamahata at intel.com>
   All Rights Reserved.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <shim_internal.h>

static void __dump_regs(const struct shim_regs * regs)
{
    debug_printf("registers\n");
    debug_printf("r15 %08x r14 %08x r13 %08x r12 %08x\n",
                 regs->r15, regs->r14, regs->r13, regs->r12);
    debug_printf("r11 %08x r10 %08x r09 %08x r08 %08x\n",
                 regs->r11, regs->r10, regs->r9, regs->r8);
    debug_printf("rcx %08x rdx %08x rsi %08x rdi %08x\n",
                 regs->rcx, regs->rdx, regs->rsi, regs->rdi);
    debug_printf("rbx %08x rbp %08x\n",
                 regs->rbx, regs->rbp);
}

void __debug_regs(const char * file, const int line, const char * func,
                  const struct shim_regs * regs)
{
    debug_printf("%s:%d:%s\n", file, line, func);
    __dump_regs(regs);
}

void __debug_context(const char * file, const int line, const char * func,
                     const struct shim_context * context)
{
    const struct shim_regs * regs = context->regs;
    debug_printf("%s:%d:%s ", file, line, func);
    debug_printf("context %p resg %p\n", context, regs);
    debug_printf("syscall_nr %08x sp %p ret_ip %p\n",
                 context->syscall_nr, context->sp, context->ret_ip);
    if (regs) {
        __dump_regs(regs);
    }
}

void __debug_hex(const char * file, const int line, const char * func,
                 unsigned long * addr, int count)
{
    debug_printf("%s:%d:%s\n", file, line, func);
    while (count >= 4) {
        debug_printf("%p: %08x %08x %08x %08x\n",
                     addr,
                     addr[0], addr[1], addr[2], addr[3]);
        addr += 4;
        count -= 4;
    }
    if (count > 0) {
        debug_printf("%p: ", addr);
        for (int i = 0; i < count; i++) {
            debug_printf("%08x", addr[i]);
        }
        debug_printf("\n");
    }
}

