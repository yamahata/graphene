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

char * __bytes2hexdump(void * hex, size_t size, char * str, size_t len)
{
    static const char * ch = "0123456789abcdef";
    assert(len >= size * 3 + 1);

    uint8_t * hex_ = hex;
    for (size_t i = 0 ; i < size ; i++) {
        uint8_t h = hex_[i];
        str[i * 3] = ch[h / 16];
        str[i * 3 + 1] = ch[h % 16];
        str[i * 3 + 2] = ' ';
    }

    str[size * 3] = 0;
    return str;
}

#define alloca_bytes2hexdump(array, size)                               \
    __bytes2hexdump((array), (size), __alloca((size) * 3 + 1), (size) * 3 + 1)

static inline struct atomic_int * get_event_nest()
{
    struct enclave_tls * tls = get_enclave_tls();
    return &tls->event_nest;
}

typedef struct {
    PAL_IDX             event_num;
    PAL_CONTEXT *       context;
    sgx_context_t *     uc;
    PAL_XREGS_STATE *   xregs_state;
    bool                retry_event;
} PAL_EVENT;

static void _DkGenericEventTrigger (PAL_IDX event_num, PAL_EVENT_HANDLER upcall,
                                    PAL_NUM arg, PAL_CONTEXT * context,
                                    sgx_context_t * uc,
                                    PAL_XREGS_STATE * xregs_state,
                                    bool retry_event)
{
    assert((((uintptr_t)xregs_state) % PAL_XSTATE_ALIGN) == 0);
    assert((PAL_XREGS_STATE*) (uc + 1) == xregs_state);

    PAL_EVENT event = {
        .event_num = event_num,
        .context = context,
        .uc = uc,
        .xregs_state = xregs_state,
        .retry_event = retry_event,
    };

    SGX_DBG(DBG_E, "_DkGenericEventTrigger\n");
    (*upcall) ((PAL_PTR) &event, arg, context);
    SGX_DBG(DBG_E, "_DkGenericEventTriger done\n");
}

static bool
_DkGenericSignalHandle (int event_num, PAL_NUM arg, PAL_CONTEXT * context,
                        sgx_context_t * uc, PAL_XREGS_STATE * xregs_state,
                        bool retry_event)
{
    assert((((uintptr_t)xregs_state) % PAL_XSTATE_ALIGN) == 0);
    assert((PAL_XREGS_STATE*) (uc + 1) == xregs_state);

    PAL_EVENT_HANDLER upcall = _DkGetExceptionHandler(event_num);

    if (upcall) {
        _DkGenericEventTrigger(event_num, upcall, arg, context, uc, xregs_state,
                               retry_event);
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

static void restore_sgx_context (sgx_context_t * uc,
                                 PAL_XREGS_STATE * xregs_state,
                                 bool retry_event,
                                 bool debug_message)
{
    atomic_dec(get_event_nest());
    if (debug_message) {
        SGX_DBG(DBG_E, "uc %p rsp 0x%08lx &rsp: %p rip 0x%08lx &rip: %p xregs_state: %p retry: %d uc+1: %p\n",
                uc, uc->rsp, &uc->rsp, uc->rip, &uc->rip,
                xregs_state, retry_event, uc + 1);
    }
    assert((((uintptr_t)xregs_state) % PAL_XSTATE_ALIGN) == 0);
    assert((PAL_XREGS_STATE*) (uc + 1) == xregs_state);

    restore_xregs(xregs_state);
    if (retry_event) {
        __restore_sgx_context_retry(uc);
    } else
        __restore_sgx_context(uc);
}

static void restore_pal_context (
    sgx_context_t * uc, PAL_XREGS_STATE * xregs_state,
    PAL_CONTEXT * ctx, bool retry_event,
    bool debug_message)
{
    assert((((uintptr_t)xregs_state) % PAL_XSTATE_ALIGN) == 0);
    assert((PAL_XREGS_STATE*) (uc + 1) == xregs_state);

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

    if (ctx->fpregs == NULL)
        memcpy(xregs_state, &SYNTHETIC_STATE, SYNTHETIC_STATE_SIZE);
    else if (xregs_state != ctx->fpregs)
        memcpy(xregs_state, ctx->fpregs,
               ctx->fpregs->fpstate.sw_reserved.xstate_size);
    /* TODO sanity check of user supplied ctx->fpregs */

    restore_sgx_context(uc, xregs_state, retry_event, debug_message);
}

static void save_pal_context (PAL_CONTEXT * ctx, sgx_context_t * uc,
                              PAL_XREGS_STATE * xregs_state)
{
    assert((((uintptr_t)xregs_state) % PAL_XSTATE_ALIGN) == 0);
    assert((PAL_XREGS_STATE*) (uc + 1) == xregs_state);

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
    union pal_csgsfs csgsfs = {
        .cs = 0x33, // __USER_CS(5) | 0(GDT) | 3(RPL)
        .fs = 0,
        .gs = 0,
        .ss = 0x2b, // __USER_DS(6) | 0(GDT) | 3(RPL)
    };
    ctx->csgsfs = csgsfs.csgsfs;

    ctx->fpregs = xregs_state;
    PAL_FPX_SW_BYTES * fpx_sw = &xregs_state->fpstate.sw_reserved;
    fpx_sw->magic1 = PAL_FP_XSTATE_MAGIC1;
    fpx_sw->extended_size = xsave_size;
    fpx_sw->xfeatures = xsave_features;
    fpx_sw->xstate_size = xsave_size + PAL_FP_XSTATE_MAGIC2_SIZE;
    memset(fpx_sw->padding, 0, sizeof(fpx_sw->padding));
    *(__typeof__(PAL_FP_XSTATE_MAGIC2)*)((void*)xregs_state + xsave_size) =
        PAL_FP_XSTATE_MAGIC2;
}

static bool handle_ud(sgx_context_t * uc)
{
    unsigned char * instr = (unsigned char *) uc->rip;
    if (instr[0] == 0xcc) { /* skip int 3 */
        uc->rip++;
        return true;
    } else if (instr[0] == 0x0f && instr[1] == 0xa2) {
        /* cpuid */
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
        /* rdtsc */
        uc->rip += 2;
        unsigned long high;
        unsigned long low;
        ocall_rdtsc(&low, &high);
        uc->rdx = high;
        uc->rax = low;
        return true;
    } else if (instr[0] == 0x0f && instr[1] == 0x05) {
        /* syscall: LibOS knows how to handle this */
        return false;
    }
    SGX_DBG(DBG_E, "unknown instruction rip 0x%016lx %s\n", uc->rip,
            alloca_bytes2hexdump(instr, 32 /* at least 2 instructions */));
    return false;
}

static void _DkExceptionHandlerLoop (PAL_CONTEXT * ctx, sgx_context_t * uc,
                                     PAL_XREGS_STATE * xregs_state)
{
    if (GET_ENCLAVE_TLS(event_nest.counter) > 0)
        SGX_DBG(DBG_E, "ctx %p uc %p xresg %p flags 0x%lx sigbit 0x%lx\n",
                ctx, uc, xregs_state,
                GET_ENCLAVE_TLS(flags), GET_ENCLAVE_TLS(pending_async_event));
    struct enclave_tls * tls = get_enclave_tls();
    do {
        int event_num = ffsl(GET_ENCLAVE_TLS(pending_async_event));
        if (event_num-- > 0 &&
            test_and_clear_bit(event_num, &tls->pending_async_event)) {
            SGX_DBG(DBG_E, "event_num %d flags 0x%lx sigbit 0x%lx\n",
                    event_num,
                    GET_ENCLAVE_TLS(flags), GET_ENCLAVE_TLS(pending_async_event));

            ctx->err = 0;
            ctx->trapno = event_num;
            ctx->oldmask = 0;
            ctx->cr2 = 0;

            _DkGenericSignalHandle(event_num, 0, ctx,
                                   uc, xregs_state, true);
            continue;
        }
    } while (test_and_clear_bit(SGX_TLS_FLAGS_ASYNC_EVENT_PENDING_BIT,
                                &tls->flags));
    if (GET_ENCLAVE_TLS(event_nest.counter) > 0)
        SGX_DBG(DBG_E, "Loop exiting\n");
}

void _DkExceptionHandlerMore (sgx_context_t * uc)
{
    atomic_inc(get_event_nest());

    PAL_XREGS_STATE * xregs_state = (PAL_XREGS_STATE *)(uc + 1);
    SGX_DBG(DBG_E, "uc %p xregs_state %p\n", uc, xregs_state);
    assert((((uintptr_t)xregs_state) % PAL_XSTATE_ALIGN) == 0);
    save_xregs(xregs_state);

    PAL_CONTEXT ctx;
    save_pal_context(&ctx, uc, xregs_state);
    _DkExceptionHandlerLoop(&ctx, uc, xregs_state);
    restore_pal_context(uc, xregs_state, &ctx, true, true);
}

void _DkExceptionHandler (unsigned int exit_info, sgx_context_t * uc)
{
    atomic_inc(get_event_nest());

    PAL_XREGS_STATE * xregs_state = (PAL_XREGS_STATE *)(uc + 1);
    SGX_DBG(DBG_E, "uc %p xregs_state %p\n", uc, xregs_state);
    assert((((uintptr_t)xregs_state) % PAL_XSTATE_ALIGN) == 0);
    save_xregs(xregs_state);

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
    SGX_DBG(DBG_E,
            "exit_info 0x%08x vector 0x%04x type 0x%04x reserved %x valid %d\n",
            exit_info, ei.info.vector, ei.info.type, ei.info.reserved,
            ei.info.valid);

    int event_num;
    if (!ei.info.valid) {
        event_num = exit_info;
    } else {
        switch (ei.info.vector) {
        case SGX_EXCEPTION_VECTOR_DE:
            event_num = PAL_EVENT_ARITHMETIC_ERROR;
            break;
        case SGX_EXCEPTION_VECTOR_BR:
            event_num = PAL_EVENT_NUM_BOUND;
            break;
        case SGX_EXCEPTION_VECTOR_UD:
            if (handle_ud(uc)) {
                restore_sgx_context(uc, xregs_state, true, true);
                /* NOTREACHED */
            }
            event_num = PAL_EVENT_ILLEGAL;
            break;
        case SGX_EXCEPTION_VECTOR_MF:
            event_num = PAL_EVENT_ARITHMETIC_ERROR;
            break;
        case SGX_EXCEPTION_VECTOR_AC:
            event_num = PAL_EVENT_MEMFAULT;
            break;
        case SGX_EXCEPTION_VECTOR_XM:
            event_num = PAL_EVENT_ARITHMETIC_ERROR;
            break;
        case SGX_EXCEPTION_VECTOR_DB:
        case SGX_EXCEPTION_VECTOR_BP:
        default:
            restore_sgx_context(uc, xregs_state, true, true);
            return;
        }
    }
    if (ADDR_IN_PAL(uc->rip) &&
        /* event isn't asynchronous */
        (event_num != PAL_EVENT_QUIT &&
         event_num != PAL_EVENT_SUSPEND &&
         event_num != PAL_EVENT_RESUME)) {
        printf("*** An unexpected AEX vector occurred inside PAL. "
               "Exiting the thread. *** \n"
               "(vector = 0x%x, type = 0x%x valid = %d, RIP = +%08lx)\n"
               "tid: %d rip: 0x%08lx\n"
               "rax: 0x%08lx rcx: 0x%08lx rdx: 0x%08lx rbx: 0x%08lx\n"
               "rsp: 0x%08lx rbp: 0x%08lx rsi: 0x%08lx rdi: 0x%08lx\n"
               "r8 : 0x%08lx r9 : 0x%08lx r10: 0x%08lx r11: 0x%08lx\n"
               "r12: 0x%08lx r13: 0x%08lx r14: 0x%08lx r15: 0x%08lx\n"
               "rflags: 0x%08lx rip: 0x%08lx\n",
               ei.info.vector, ei.info.type, ei.info.valid,
               uc->rip - (uintptr_t) TEXT_START,
               current_tid(), uc->rip,
               uc->rax, uc->rcx, uc->rdx, uc->rbx,
               uc->rsp, uc->rbp, uc->rsi, uc->rdi,
               uc->r8, uc->r9, uc->r10, uc->r11,
               uc->r12, uc->r13, uc->r14, uc->r15,
               uc->rflags, uc->rip);
#ifdef DEBUG
        printf("%s\n",
               alloca_bytes2hexdump((uint8_t*)uc->rip,
                                    32 /* at least 2 instructions */));
        printf("pausing for debug\n");
        while (true)
            __asm__ volatile("hlt");
#endif
        _DkThreadExit();
    }

    SGX_DBG(DBG_E, "rip 0x%08lx\n", uc->rip);

    PAL_CONTEXT ctx;
    save_pal_context(&ctx, uc, xregs_state);

    /* TODO: save EXINFO in MISC regsion and populate those */
    ctx.err = 0;
    ctx.trapno = ei.info.valid? ei.info.vector: event_num;
    ctx.oldmask = 0;
    ctx.cr2 = 0;

    struct enclave_tls * tls = get_enclave_tls();
    clear_bit(SGX_TLS_FLAGS_ASYNC_EVENT_PENDING_BIT, &tls->flags);
    clear_bit(event_num, &tls->pending_async_event);
    /* TODO: When EXINFO in MISC region is supported. retrieve address
     * information from MISC
     */
    PAL_NUM arg = 0;
    switch (event_num) {
    case PAL_EVENT_ILLEGAL:
        arg = uc->rip;
        break;
    case PAL_EVENT_MEMFAULT:
        /* TODO */
        break;
    default:
        /* nothing */
        break;
    }
    _DkGenericSignalHandle(event_num, arg, &ctx, uc, xregs_state, true);

    _DkExceptionHandlerLoop(&ctx, uc, xregs_state);
    restore_pal_context(uc, xregs_state, &ctx, true, true);
}

void _DkRaiseFailure (int error)
{
    PAL_EVENT_HANDLER upcall = _DkGetExceptionHandler(PAL_EVENT_FAILURE);

    if (!upcall)
        return;

    PAL_EVENT event = {
        .event_num   = PAL_EVENT_FAILURE,
        .context     = NULL,
        .uc          = NULL,
        .xregs_state = NULL,
        .retry_event = false
    };

    (*upcall) ((PAL_PTR) &event, error, NULL);
}

void _DkExceptionReturn (void * event)
{
    PAL_EVENT * e = event;
    PAL_CONTEXT * ctx = e->context;

    if (!ctx) {
        return;
    }

    SGX_DBG(DBG_E,
            "uc %p rsp 0x%08lx &rsp: %p rip 0x%08lx &rip: %p "
            "xregs_state %p event_nest %ld\n",
            e->uc, e->uc->rsp, &e->uc->rsp, e->uc->rip, &e->uc->rip, e->xregs_state,
            atomic_read(get_event_nest()));
    assert((((uintptr_t)e->xregs_state) % PAL_XSTATE_ALIGN) == 0);
    assert((PAL_XREGS_STATE*) (e->uc + 1) == e->xregs_state);

    restore_pal_context(e->uc, e->xregs_state, ctx, e->retry_event, true);
}

void _DkHandleExternalEvent (PAL_NUM event, sgx_context_t * uc,
                             PAL_XREGS_STATE * xregs_state)
{
    struct atomic_int * event_nest = get_event_nest();
    assert((((uintptr_t)xregs_state) % PAL_XSTATE_ALIGN) == 0);
    assert((PAL_XREGS_STATE*) (uc + 1) == xregs_state);

    PAL_CONTEXT ctx;
    save_pal_context(&ctx, uc, xregs_state);
    ctx.err = 0;
    ctx.trapno = event; /* XXX TODO: what kind of value should be returned in
                         * trapno. This is very implementation specific
                         */
    ctx.oldmask = 0;
    ctx.cr2 = 0;

    if (event != 0) {
        SGX_DBG(DBG_E,
                "event %ld uc %p rsp 0x%08lx &rsp: %p rip 0x%08lx &rip: %p "
                "xregs_state %p event_nest %ld\n",
                event, uc, uc->rsp, &uc->rsp, uc->rip, &uc->rip, xregs_state,
                atomic_read(event_nest));
        atomic_inc(event_nest);
        if (!_DkGenericSignalHandle(event, 0, &ctx, uc, xregs_state, false/*true*/)
            && event != PAL_EVENT_RESUME)
            _DkThreadExit();
        atomic_dec(event_nest);
    }

#if 0
    //bool retry_event = (atomic_read(event_nest) == 0);
    atomic_inc(event_nest);
    //restore_pal_context(uc, xregs_state, &ctx, retry_event, false);
    restore_pal_context(uc, xregs_state, &ctx, false, false);
#endif
}
