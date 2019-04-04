#include <asm-offsets-build.h>

#include <stddef.h>

#include <shim_defs.h>
#include <shim_internal.h>
#include <shim_tls.h>
#include <shim_thread.h>
#include <shim_types.h>

void dummy(void)
{
    /* shim_tcb_t */
#ifdef SHIM_TCB_USE_GS
    OFFSET_T(SHIM_TCB_OFFSET, PAL_TCB, libos_tcb);
#else
    OFFSET_T(SHIM_TCB_OFFSET, __libc_tcb_t, shim_tcb);
#endif
    OFFSET_T(TCB_SELF, shim_tcb_t, self);
    OFFSET_T(TCB_TP, shim_tcb_t, tp);
    OFFSET_T(TCB_SYSCALL_NR, shim_tcb_t, context.syscall_nr);
    OFFSET_T(TCB_SP, shim_tcb_t, context.sp);
    OFFSET_T(TCB_RET_IP, shim_tcb_t, context.ret_ip);
    OFFSET_T(TCB_REGS, shim_tcb_t, context.regs);
#ifdef SHIM_SYSCALL_STACK
    OFFSET_T(TCB_SYSCALL_STACK, shim_tcb_t, syscall_stack);
#endif
    OFFSET_T(TCB_FLAGS, shim_tcb_t, flags);

    /* struct shim_thread */
    OFFSET(THREAD_HAS_SIGNAL, shim_thread, has_signal);

    /* definitions */
    DEFINE(SIGFRAME_SIZE, sizeof(struct sigframe));
    DEFINE(FP_XSTATE_SIZE, sizeof(struct _libc_fpstate));
    DEFINE(FP_XSTATE_MAGIC2_SIZE, FP_XSTATE_MAGIC2_SIZE);
    DEFINE(REDZONE_SIZE, REDZONE_SIZE);
}
