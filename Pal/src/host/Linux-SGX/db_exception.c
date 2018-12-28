/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* Copyright (C) 2014 Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * db_signal.c
 *
 * This file contains APIs to set up handlers of exceptions issued by the
 * host, and the methods to pass the exceptions to the upcalls.
 */

#include "pal_defs.h"
#include "pal_linux_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_error.h"
#include "pal_security.h"
#include "api.h"
#include "ecall_types.h"

#include <atomic.h>
#include <sigset.h>
#include <linux/signal.h>
#include <ucontext.h>

typedef struct exception_event {
    PAL_IDX             event_num;
    PAL_CONTEXT *       context;
} PAL_EVENT;

static void _DkGenericEventTrigger (PAL_IDX event_num, PAL_EVENT_HANDLER upcall,
                                    PAL_NUM arg, PAL_CONTEXT * context)
{
    struct exception_event event;

    event.event_num = event_num;
    event.context = context;

    (*upcall) ((PAL_PTR) &event, arg, context);
}

static bool
_DkGenericSignalHandle (int event_num, PAL_NUM arg, PAL_CONTEXT * context)
{
    PAL_EVENT_HANDLER upcall = _DkGetExceptionHandler(event_num);

    if (upcall) {
        _DkGenericEventTrigger(event_num, upcall, arg, context);
        return true;
    }

    return false;
}

#define ADDR_IN_PAL(addr)  \
        ((void *) (addr) > TEXT_START && (void *) (addr) < TEXT_END)

PAL_BOL DkInPal (const PAL_CONTEXT * context)
{
    return context && ADDR_IN_PAL(context->rip);
}

static void restore_sgx_context (sgx_context_t * uc)
{
    SGX_DBG(DBG_E, "uc %p rsp 0x%08lx &rsp: %p rip 0x%08lx &rip: %p\n",
            uc, uc->rsp, &uc->rsp, uc->rip, &uc->rip);
    restore_xregs((uint64_t)(uc + 1));
    __restore_sgx_context(uc);
}

static void restore_pal_context (sgx_context_t * uc, PAL_CONTEXT * ctx)
{
    uc->rax = ctx->rax;
    uc->rbx = ctx->rbx;
    uc->rcx = ctx->rcx;
    uc->rdx = ctx->rdx;
    uc->rsp = ctx->rsp;
    uc->rbp = ctx->rbp;
    uc->rsi = ctx->rsi;
    uc->rdi = ctx->rdi;
    uc->r8  = ctx->r8;
    uc->r9  = ctx->r9;
    uc->r10 = ctx->r10;
    uc->r11 = ctx->r11;
    uc->r12 = ctx->r12;
    uc->r13 = ctx->r13;
    uc->r14 = ctx->r14;
    uc->r15 = ctx->r15;
    uc->rflags = ctx->efl;
    uc->rip = ctx->rip;

    restore_sgx_context(uc);
}

static void save_pal_context (PAL_CONTEXT * ctx, sgx_context_t * uc)
{
    memset(ctx, 0, sizeof(*ctx));

    ctx->rax = uc->rax;
    ctx->rbx = uc->rbx;
    ctx->rcx = uc->rcx;
    ctx->rdx = uc->rdx;
    ctx->rsp = uc->rsp;
    ctx->rbp = uc->rbp;
    ctx->rsi = uc->rsi;
    ctx->rdi = uc->rdi;
    ctx->r8  = uc->r8;
    ctx->r9  = uc->r9;
    ctx->r10 = uc->r10;
    ctx->r11 = uc->r11;
    ctx->r12 = uc->r12;
    ctx->r13 = uc->r13;
    ctx->r14 = uc->r14;
    ctx->r15 = uc->r15;
    ctx->efl = uc->rflags;
    ctx->rip = uc->rip;
    /* .cs = 0x33, .fs = 0, .gs = 0 .ss = 0x2b */
    ctx->csgsfs = (0x33UL << 24) | 0x2bUL;
}

static PAL_BOL handle_ud(sgx_context_t * uc)
{
    unsigned char * instr = (unsigned char *) uc->rip;
    if (instr[0] == 0xcc) { /* skip int 3 */
        uc->rip++;
        return true;
    } else if (instr[0] == 0x0f && instr[1] == 0xa2) {
        unsigned int values[4];
        if (!_DkCpuIdRetrieve(uc->rax & 0xffffffff,
                              uc->rcx & 0xffffffff, values)) {
            uc->rip += 2;
            uc->rax = values[0];
            uc->rbx = values[1];
            uc->rcx = values[2];
            uc->rdx = values[3];
            return true;
        }
    } else if (instr[0] == 0x0f && instr[1] == 0x31) {
        uc->rip += 2;
        unsigned long high;
        unsigned long low;
        ocall_rdtsc(&low, &high);
        uc->rdx = high;
        uc->rax = low;
        return true;
    }
    return false;
}

void _DkExceptionHandler (unsigned int exit_info, sgx_context_t * uc)
{
    save_xregs((uint64_t)(uc + 1));

#if SGX_HAS_FSGSBASE == 0
    /* set the FS first if necessary */
    uint64_t fsbase = (uint64_t) GET_ENCLAVE_TLS(fsbase);
    if (fsbase)
        wrfsbase(fsbase);
#endif

    union {
        sgx_arch_exitinfo_t info;
        int intval;
    } ei = { .intval = exit_info };

    int event_num;
    if (!ei.info.valid) {
        event_num = exit_info;
    } else {
        switch (ei.info.vector) {
        case SGX_EXCEPTION_VECTOR_UD:
            if (handle_ud(uc)) {
                restore_sgx_context(uc);
                /* NOTREACHED */
            }
            event_num = PAL_EVENT_ILLEGAL;
            break;
        case SGX_EXCEPTION_VECTOR_DE:
            event_num = PAL_EVENT_DIVZERO;
            break;
        case SGX_EXCEPTION_VECTOR_AC:
            event_num = PAL_EVENT_MEMFAULT;
            break;
        default:
            restore_sgx_context(uc);
            return;
        }
    }
    if (ADDR_IN_PAL(uc->rip)) {
        printf("*** An unexpected AEX vector occurred inside PAL. "
               "Exiting the thread. "
               "(vector = 0x%x, type = 0x%x valid = %d, RIP = +%08lx) ***\n",
               ei.info.vector, ei.info.type, ei.info.valid,
               uc->rip - (uintptr_t) TEXT_START);
#ifdef DEBUG
        while (true)
            asm volatile("hlt");
#endif
        _DkThreadExit();
    }

    PAL_CONTEXT ctx;
    save_pal_context(&ctx, uc);

    /* TODO: save EXINFO in MISC regsion and populate those */
    ctx.err = 0;
    ctx.trapno = ei.info.valid? ei.info.vector: event_num;
    ctx.oldmask = 0;
    ctx.cr2 = 0;

    PAL_NUM arg = 0;
    _DkGenericSignalHandle(event_num, arg, &ctx);

    restore_pal_context(uc, &ctx);
}

void _DkRaiseFailure (int error)
{
    PAL_EVENT_HANDLER upcall = _DkGetExceptionHandler(PAL_EVENT_FAILURE);

    if (!upcall)
        return;

    PAL_EVENT event;
    event.event_num = PAL_EVENT_FAILURE;
    event.context   = NULL;

    (*upcall) ((PAL_PTR) &event, error, NULL);
}

void _DkExceptionReturn (void * event)
{
    PAL_EVENT * e = event;
    sgx_context_t uc;
    PAL_CONTEXT * ctx = e->context;

    if (!ctx) {
        return;
    }
    restore_pal_context(&uc, ctx);
}

void _DkHandleExternalEvent (PAL_NUM event, sgx_context_t * uc,
                             PAL_XREGS_STATE * xregs_state)
{
    SGX_DBG(DBG_E, "_DkHandleExternalEvent "
            "uc %p rsp 0x%08lx &rsp: %p rip 0x%08lx &rip: %p\n",
            uc, uc->rsp, &uc->rsp, uc->rip, &uc->rip);

    PAL_CONTEXT ctx;
    save_pal_context(&ctx, uc);
    ctx.err = 0;
    ctx.trapno = event; /* XXX TODO: what kind of value should be returned in
                         * trapno. This is very implementation specific
                         */
    ctx.oldmask = 0;
    ctx.cr2 = 0;

    if (!_DkGenericSignalHandle(event, 0, &ctx)
        && event != PAL_EVENT_RESUME)
        _DkThreadExit();
}
