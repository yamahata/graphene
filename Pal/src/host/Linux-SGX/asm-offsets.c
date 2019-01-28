#include <stddef.h>

#include "pal.h"
#include "sgx_arch.h"
#include "sgx_tls.h"

#include <asm-offsets-build.h>

void dummy(void)
{
    /* sgx_arch_gpr_t */
    OFFSET_T(SGX_GPR_RAX, sgx_arch_gpr_t, rax);
    OFFSET_T(SGX_GPR_RCX, sgx_arch_gpr_t, rcx);
    OFFSET_T(SGX_GPR_RDX, sgx_arch_gpr_t, rdx);
    OFFSET_T(SGX_GPR_RBX, sgx_arch_gpr_t, rbx);
    OFFSET_T(SGX_GPR_RSP, sgx_arch_gpr_t, rsp);
    OFFSET_T(SGX_GPR_RBP, sgx_arch_gpr_t, rbp);
    OFFSET_T(SGX_GPR_RSI, sgx_arch_gpr_t, rsi);
    OFFSET_T(SGX_GPR_RDI, sgx_arch_gpr_t, rdi);
    OFFSET_T(SGX_GPR_R8, sgx_arch_gpr_t, r8);
    OFFSET_T(SGX_GPR_R9, sgx_arch_gpr_t, r9);
    OFFSET_T(SGX_GPR_R10, sgx_arch_gpr_t, r10);
    OFFSET_T(SGX_GPR_R11, sgx_arch_gpr_t, r11);
    OFFSET_T(SGX_GPR_R12, sgx_arch_gpr_t, r12);
    OFFSET_T(SGX_GPR_R13, sgx_arch_gpr_t, r13);
    OFFSET_T(SGX_GPR_R14, sgx_arch_gpr_t, r14);
    OFFSET_T(SGX_GPR_R15, sgx_arch_gpr_t, r15);
    OFFSET_T(SGX_GPR_RFLAGS, sgx_arch_gpr_t, rflags);
    OFFSET_T(SGX_GPR_RIP, sgx_arch_gpr_t, rip);
    OFFSET_T(SGX_GPR_EXITINFO, sgx_arch_gpr_t, exitinfo);

    /* sgx_context_t */
    OFFSET_T(SGX_CONTEXT_RAX, sgx_context_t, rax);
    OFFSET_T(SGX_CONTEXT_RCX, sgx_context_t, rcx);
    OFFSET_T(SGX_CONTEXT_RDX, sgx_context_t, rdx);
    OFFSET_T(SGX_CONTEXT_RBX, sgx_context_t, rbx);
    OFFSET_T(SGX_CONTEXT_RSP, sgx_context_t, rsp);
    OFFSET_T(SGX_CONTEXT_RBP, sgx_context_t, rbp);
    OFFSET_T(SGX_CONTEXT_RSI, sgx_context_t, rsi);
    OFFSET_T(SGX_CONTEXT_RDI, sgx_context_t, rdi);
    OFFSET_T(SGX_CONTEXT_R8, sgx_context_t, r8);
    OFFSET_T(SGX_CONTEXT_R9, sgx_context_t, r9);
    OFFSET_T(SGX_CONTEXT_R10, sgx_context_t, r10);
    OFFSET_T(SGX_CONTEXT_R11, sgx_context_t, r11);
    OFFSET_T(SGX_CONTEXT_R12, sgx_context_t, r12);
    OFFSET_T(SGX_CONTEXT_R13, sgx_context_t, r13);
    OFFSET_T(SGX_CONTEXT_R14, sgx_context_t, r14);
    OFFSET_T(SGX_CONTEXT_R15, sgx_context_t, r15);
    OFFSET_T(SGX_CONTEXT_RFLAGS, sgx_context_t, rflags);
    OFFSET_T(SGX_CONTEXT_RIP, sgx_context_t, rip);
    DEFINE(SGX_CONTEXT_SIZE, sizeof(sgx_context_t));
    DEFINE(SGX_CONTEXT_XSTATE_ALIGN_SUB,
           sizeof(sgx_context_t) % PAL_XSTATE_ALIGN);

    /* struct enclave_tls */
    OFFSET_U(SGX_SELF, enclave_tls, self);
    OFFSET_U(SGX_ENCLAVE_SIZE, enclave_tls, enclave_size);
    OFFSET_U(SGX_TCS_OFFSET, enclave_tls, tcs_offset);
    OFFSET_U(SGX_INITIAL_STACK_OFFSET, enclave_tls, initial_stack_offset);
    OFFSET_U(SGX_SIG_STACK_LOW, enclave_tls, sig_stack_low);
    OFFSET_U(SGX_SIG_STACK_HIGH, enclave_tls, sig_stack_high);
    OFFSET_U(SGX_FLAGS, enclave_tls, flags);
    OFFSET_U(SGX_PENDING_ASYNC_EVENT, enclave_tls, pending_async_event);
    OFFSET_U(SGX_EVENT_NEST, enclave_tls, event_nest.counter);
    OFFSET_U(SGX_AEP, enclave_tls, aep);
    OFFSET_U(SGX_SSA, enclave_tls, ssa);
    OFFSET_U(SGX_GPR, enclave_tls, gpr);
    OFFSET_U(SGX_EXIT_TARGET, enclave_tls, exit_target);
    OFFSET_U(SGX_FSBASE, enclave_tls, fsbase);
    OFFSET_U(SGX_STACK, enclave_tls, stack);
    OFFSET_U(SGX_USTACK_TOP, enclave_tls, ustack_top);
    OFFSET_U(SGX_USTACK, enclave_tls, ustack);
    OFFSET_U(SGX_THREAD, enclave_tls, thread);

    DEFINE(SGX_TLS_FLAGS_ASYNC_EVENT_PENDING_BIT,
           SGX_TLS_FLAGS_ASYNC_EVENT_PENDING_BIT);
    DEFINE(SGX_TLS_FLAGS_EVENT_EXECUTING_BIT,
           SGX_TLS_FLAGS_EVENT_EXECUTING_BIT);
    DEFINE(PAL_ASYNC_EVENT_MASK, PAL_ASYNC_EVENT_MASK);

    /* sgx_arch_tcs_t */
    DEFINE(TCS_SIZE, sizeof(sgx_arch_tcs_t));

    /* fp regs */
    OFFSET_T(XSAVE_HEADER_OFFSET, PAL_XREGS_STATE, header);
    DEFINE(PAL_XSTATE_ALIGN, PAL_XSTATE_ALIGN);
    DEFINE(PAL_FP_XSTATE_MAGIC2_SIZE, PAL_FP_XSTATE_MAGIC2_SIZE);

    /* PAL_EVENT */
    DEFINE(PAL_EVENT_QUIT, PAL_EVENT_QUIT);
    DEFINE(PAL_EVENT_SUSPEND, PAL_EVENT_SUSPEND);
    DEFINE(PAL_EVENT_RESUME, PAL_EVENT_RESUME);
}
