#include "sgx_arch.h"
#include "asm-offsets.h"

.macro WRFSBASE_RBX
	.byte 0xf3, 0x48, 0x0f, 0xae, 0xd3 /* WRFSBASE %RBX */
.endm

.macro SGX_TLS_FLAGS_SET_EXECUTING_BIT reg
	movq %gs:SGX_SELF, \reg
	addq $SGX_FLAGS, \reg
	lock btsq $SGX_TLS_FLAGS_EVENT_EXECUTING_BIT, (\reg)
.endm

.macro SGX_TLS_FLAGS_CLEAR_EXECUTING_BIT reg
	movq %gs:SGX_SELF, \reg
	addq $SGX_FLAGS, \reg
	lock btrq $SGX_TLS_FLAGS_EVENT_EXECUTING_BIT, (\reg)
.endm

	.extern ecall_table
	.extern enclave_ecall_pal_main

	.global enclave_entry
	.type enclave_entry, @function

enclave_entry:
	# On EENTER/ERESUME, RAX is the current SSA, RBX is the address of TCS,
	# RCX is the address of AEP. Other registers are not trusted.

	# current SSA is in RAX (Trusted)
	cmpq $0, %rax
	jne .Lhandle_resume

	# TCS is in RBX (Trusted)

	# AEP address in RCX (Trusted)
	movq %rcx, %gs:SGX_AEP

	# The following code is hardened to defend attacks from untrusted host.
	# Any states given by the host instead of the ISA must be assumed
	# potentially malicious.
	#
	# For instance, Jo Van Bulck contributed a detailed vulnerability report
	# in https://github.com/oscarlab/graphene/issues/28. (Fixed)
	# Brief description of the vulnerabilities:
	# The previous implementation does not check the index of entry
	# functions (RDI at enclave entry) given by the untrusted PAL.
	# An attacker can cause overflow/underflow to jump to random
	# locaion in enclaves. Moreover, we used a specific index
	# (RETURN_FROM_OCALL) to tell if the control flow is returned
	# from a OCALL in the untrusted PAL. Attackers can manipulate RDI
	# to deceive the trusted PAL.

	# A safe design: check if %gs:SGX_EXIT_TARGET is ever assigned
	movq %gs:SGX_EXIT_TARGET, %rcx
	cmpq $0, %rcx
	jne .Lreturn_from_ocall

	# PAL convention:
	# RDI - index in ecall_table
	# RSI - prointer to ecall arguments
	# RDX - exit target
	# RCX (former RSP) - The unstrusted stack
	# R8  - enclave base

	# calculate enclave base = RBX (trusted) - %gs:SGX_TCS_OFFSET
	subq %gs:SGX_TCS_OFFSET, %rbx
	movq %rbx, %r8

	# push untructed stack address to RCX
	movq %rsp, %rcx

	# switch to enclve stack: enclave base + %gs:SGX_INITIAL_STACK_OFFSET
	addq %gs:SGX_INITIAL_STACK_OFFSET, %rbx
	movq %rbx, %rsp

	# clear the rest of register states
	xorq %rax, %rax
	xorq %rbx, %rbx
	xorq %r9,  %r9
	xorq %r10, %r10
	xorq %r11, %r11
	xorq %r12, %r12
	xorq %r13, %r13
	xorq %r14, %r14
	xorq %r15, %r15

	# register states need to be carefully checked, so we move the handling
	# to handle_ecall() in enclave_ecalls.c
	callq handle_ecall

	# never return to this point (should die)
	xorq %rdi, %rdi
	xorq %rsi, %rsi
	jmp .Leexit

.Lhandle_resume:
	# PAL convention:
	# RDI - external event

	# get some information from GPR
	movq %gs:SGX_GPR, %rbx

	movq %rdi, %rsi
	xorq %rdi, %rdi
	movl SGX_GPR_EXITINFO(%rbx), %edi
	testl $0x80000000, %edi
	jnz .Lhandle_exception

	movl %esi, %edi
	# use external event - only the first 8 bits count
	andl $0xff, %edi
	cmpl $0, %edi
	jne .Lhandle_exception_raise

#if SGX_HAS_FSGSBASE == 0
	movq %gs:SGX_FSBASE, %rdi
	cmpq $0, %rdi
	je .Ljust_resume

	movq SGX_GPR_RSP(%rbx), %rsi
	subq $16, %rsi
	movq %rsi, SGX_GPR_RSP(%rbx)

	# try to push rip and fsbase onto the stack
	movq %rdi, (%rsi)
	movq SGX_GPR_RIP(%rbx), %rdi
	movq %rdi, 8(%rsi)

	# new RIP is the resume point
	leaq .Lafter_resume(%rip), %rdi
	movq %rdi, SGX_GPR_RIP(%rbx)

.Ljust_resume:
#endif
	# clear the registers
	xorq %rdi, %rdi
	xorq %rsi, %rsi

	# exit address in RDX, mov it to RBX
	movq %rdx, %rbx
	movq $EEXIT, %rax
	ENCLU

#if SGX_HAS_FSGSBASE == 0
.Lafter_resume:
	movq %rbx, -8(%rsp)
	popq %rbx
	WRFSBASE_RBX
	movq -16(%rsp), %rbx
	retq
#endif

.Lhandle_exception_raise:
#if 0
	movq %gs:SGX_SELF, %rax
	addq $SGX_FLAGS, %rax
	lock btsq $SGX_TLS_FLAGS_EVENT_EXECUTING_BIT, (%rax)
#else
	SGX_TLS_FLAGS_SET_EXECUTING_BIT %rax
#endif
	jnc .Lhandle_exception__

	cmpq $PAL_EVENT_QUIT, %rdi
	je .Lpend_async_event
	cmpq $PAL_EVENT_SUSPEND, %rdi
	je .Lpend_async_event
	cmpq $PAL_EVENT_RESUME, %rdi
	je .Lpend_async_event
	jmp .Lhandle_exception__

.Lpend_async_event:
	addq $(SGX_PENDING_ASYNC_EVENT - SGX_FLAGS), %rax
	# %rdi = $PAL_EVENT_QUIT or $PAL_EVENT_SUSPEND or $PAL_EVENT_RESUME
	lock btsq %rdi, (%rax)
	subq $(SGX_PENDING_ASYNC_EVENT - SGX_FLAGS), %rax
	lock btsq $SGX_TLS_FLAGS_ASYNC_EVENT_PENDING_BIT, (%rax)
	jmp .Lhandle_exception_out

.Lhandle_exception:
#if 0
	movq %gs:SGX_SELF, %rax
	addq $SGX_FLAGS, %rax
	lock btsq $SGX_TLS_FLAGS_EVENT_EXECUTING_BIT, (%rax)
#else
	SGX_TLS_FLAGS_SET_EXECUTING_BIT %rax
#endif
.Lhandle_exception__:
	# %rbx SGX_GPR base address from TLS
	movq SGX_GPR_RSP(%rbx), %rsi

	/*
	 * when interrupted at __restore_sgx_context_need_jmp_emulate
	 * the next jmp needs to be executed. otherwise the saved
	 * rip at -REDZONE-8(%rsp) will be lost.
	 * before clobbering it, emulate jmp instruction.
	 */
	movq SGX_GPR_RIP(%rbx), %rax
	cmpq %rax, __restore_sgx_context_need_jmp_emulate(%rip)
	je .Lemulate_jmp
	cmpq %rax, __restore_sgx_context_retry_need_jmp_emulate(%rip)
	je .Lemulate_jmp
	jmp .Lstack_check
.Lemulate_jmp:
	movq - REDZONE_SIZE - 8(%rsi), %rax
	movq %rax, SGX_GPR_RIP(%rbx)
	## TODO adjust rip etc to allow to close a window to grow stack
	## unlimitedly

.Lstack_check:
	movq %gs:SGX_SIG_STACK_LOW, %rax
	cmpq %rax, %rsi
	jle .Lout_of_signal_stack
	movq %gs:SGX_SIG_STACK_HIGH, %rax
	cmpq %rax, %rsi
	jge .Lout_of_signal_stack
	jmp .Lon_signal_stack

.Lout_of_signal_stack:
	movq %gs:SGX_SIG_STACK_HIGH, %rsi
        /* staring from new stack. there is no red zone used.
         * offset it below calculation */
	addq $REDZONE_SIZE, %rsi

	/* 8 is to avoid redzone clobber */
#define STACK_PADDING_SIZE	(PAL_FP_XSTATE_MAGIC2_SIZE + 8)
#define STACK_FRAME_SUB \
	(SGX_CONTEXT_SIZE + REDZONE_SIZE + STACK_PADDING_SIZE)
.Lon_signal_stack:
	movq xsave_size@GOTPCREL(%rip), %rax
	movl (%rax), %eax
	addq $STACK_FRAME_SUB, %rax
	subq %rax, %rsi
	# Align xsave area to 64 bytes after sgx_context_t
	# SGX_CONTEXT_SIZE = sizeof(sgx_context_t) = 144
	# PAL_XSTATE_ALIGN = 64
	# SGX_CONTEXT_XSTATE_ALIGN_SUB=SGX_CONTEXT_SIZE % PAL_XSTATE_ALIGN = 16
	# unfortunatley gas doesn't understand
	# $(SGX_CONTEXT_SIZE % PAL_XSTATE_ALIGN)
	andq $~(PAL_XSTATE_ALIGN - 1), %rsi
	subq $SGX_CONTEXT_XSTATE_ALIGN_SUB, %rsi

	# we have exitinfo in RDI, swap with the one on GPR
	# and dump into the context
	xchgq %rdi, SGX_GPR_RDI(%rbx)
	movq %rdi, SGX_CONTEXT_RDI(%rsi)

	# dump the rest of context
	movq SGX_GPR_RAX(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_RAX(%rsi)
	movq SGX_GPR_RCX(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_RCX(%rsi)
	movq SGX_GPR_RDX(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_RDX(%rsi)
	movq SGX_GPR_RBX(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_RBX(%rsi)
	movq SGX_GPR_RSP(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_RSP(%rsi)
	movq SGX_GPR_RBP(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_RBP(%rsi)
	movq SGX_GPR_RSI(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_RSI(%rsi)
	/* rdi is saved above */
	movq SGX_GPR_R8(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_R8(%rsi)
	movq SGX_GPR_R9(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_R9(%rsi)
	movq SGX_GPR_R10(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_R10(%rsi)
	movq SGX_GPR_R11(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_R11(%rsi)
	movq SGX_GPR_R12(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_R12(%rsi)
	movq SGX_GPR_R13(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_R13(%rsi)
	movq SGX_GPR_R14(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_R14(%rsi)
	movq SGX_GPR_R15(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_R15(%rsi)
	movq SGX_GPR_RFLAGS(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_RFLAGS(%rsi)
	movq SGX_GPR_RIP(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_RIP(%rsi)

	movq %rsi, SGX_GPR_RSP(%rbx)
	movq %rsi, SGX_GPR_RSI(%rbx)

	/* TODO: save EXINFO in MISC region */

	# new RIP is the exception handler
	leaq _DkExceptionHandler(%rip), %rdi
	movq %rdi, SGX_GPR_RIP(%rbx)

	# FP registers are saved on entry of _DkExceptionHandler()

.Lhandle_exception_out:
	# clear the registers
	xorq %rdi, %rdi
	xorq %rsi, %rsi

	# exit address in RDX, mov it to RBX
	movq %rdx, %rbx
	movq $EEXIT, %rax
	ENCLU


	.global sgx_ocall
	.type sgx_ocall, @function

sgx_ocall:
	##
	## input:
	## %rdi: code
	## %rsi: void * ms
	##
	## sgx_context_t:
	##   rax = 0: place holder
	##   rcx
	##   ...
	##   rflags
	##   rip
	## xsave area
	##    xregs
	## (padding)
	## previous rbp
	## previous rip: pushed by callq
	##

	// defer async signal after retuning ocall.
	// See _DkHandleExternalEvent()
	SGX_TLS_FLAGS_SET_EXECUTING_BIT %rax

	pushq %rbp
	movq %rsp, %rbp

	movq xsave_size@GOTPCREL(%rip), %rax
	movl (%rax), %eax
	addq $STACK_PADDING_SIZE, %rax
	subq %rax, %rsp
	andq $~(PAL_XSTATE_ALIGN - 1), %rsp

	pushq %rdx
	pushq %rdi
	movq %rsp, %rdi
	addq $2 * 8, %rdi	/* adjust pushq %rdx; pushq %rdi above */
	callq save_xregs
	popq %rdi
	popq %rdx

	movq 8(%rbp), %rax
	pushq %rax	# previous RIP
	pushfq
	pushq %r15
	pushq %r14
	pushq %r13
	pushq %r12
	pushq %r11
	pushq %r10
	pushq %r9
	pushq %r8
	pushq %rdi
	pushq %rsi
	movq (%rbp), %rax
	pushq %rax	# previous RBP
	leaq 16(%rbp), %rax
	pushq %rax	# previous RSP
	pushq %rbx
	pushq %rdx
	pushq %rcx
	pushq $0        # place holder for RAX

	movq %rsp, %gs:SGX_STACK

	jmp .Leexit

.Lexception_handler:

.Leexit:
	movq %rdi, %rbx
	movq SYNTHETIC_STATE@GOTPCREL(%rip), %rdi
	callq restore_xregs
	movq %rbx, %rdi

	xorq %rdx, %rdx
	xorq %r8, %r8
	xorq %r9, %r9
	xorq %r10, %r10
	xorq %r11, %r11
	xorq %r12, %r12
	xorq %r13, %r13
	xorq %r14, %r14
	xorq %r15, %r15
	xorq %rbp, %rbp

	movq %gs:SGX_USTACK, %rsp
	andq $STACK_ALIGN, %rsp

	movq %gs:SGX_EXIT_TARGET, %rbx
	movq %gs:SGX_AEP, %rcx
	movq $EEXIT, %rax
	ENCLU

.Lreturn_from_ocall:
	# PAL convention:
	# RDI - return value
	# RSI - external event (if there is any)

	## sgx_context_t::rax = %rdi
	movq %gs:SGX_STACK, %rax
	movq %rdi, (%rax) # return value

	# restore FSBASE if necessary
	movq %gs:SGX_FSBASE, %rbx
	cmpq $0, %rbx
	je .Lno_fsbase
	WRFSBASE_RBX
.Lno_fsbase:
	// cmpq $0, %rsi
	//je .Lno_external_event

	movq %rsi, %rdi	## %rdi = PAL_NUM event <- RSI
	movq %rax, %rsi	## %rsi = sgx_context_t * uc
	movq %rax, %rdx
	addq $SGX_CONTEXT_SIZE, %rdx ## %rdx = PAL_XREGS_STATE * xregs_state

	movq %gs:SGX_SIG_STACK_HIGH, %rsp
	callq _DkHandleExternalEvent


	/* we shouldn't come here. Just in case to trigger error exception */
	hlt
//.Lno_external_event:
	# restore the stack
	movq %gs:SGX_STACK, %rsp

	movq %rsp, %rdi
	addq $SGX_CONTEXT_SIZE, %rdi
	callq restore_xregs

	movq %gs:SGX_STACK, %rdi
	jmp __restore_sgx_context_retry

	# void __restore_sgx_context (sgx_context_t *uc)
	# __attribute__((noreturn))
	.global __restore_sgx_context
	.type __restore_sgx_context, @function
__restore_sgx_context:
	movq %rdi, %rsp

	popq %rax
	popq %rcx
	popq %rdx
	popq %rbx
	addq $8, %rsp /* don't pop RSP yet */
	popq %rbp
	popq %rsi
	popq %rdi
	popq %r8
	popq %r9
	popq %r10
	popq %r11
	popq %r12
	popq %r13

	/* store saved %rip at -REDZONE-8(%saved rsp).
	 * notice sizeof(sgx_context_t) = 144 > 128 = REDZONE_SIZE.
	 */
	## see the definition of sgx_context_t
	## currently %rsp is pointing to %r14
	movq -10 * 8(%rsp), %r14 # %r14 = saved %rsp
	movq 3 * 8(%rsp), %r15	 # %r15 = saved %rip
	movq %r15, - REDZONE_SIZE - 8(%r14)

	popq %r14
	popq %r15
	popfq

	/* In user context, sysret nor iret isn't usable.
	 * the following two instructions need to be atomic.
	 */
	movq -13 * 8(%rsp), %rsp
	/* If interrupted here,
	 * signal handler can clobber the saved rip at -REDZONE_SIZE-8(%rsp).
	 * So singla handler emulates the following jmp instruciton before
	 * using stack.
	 * see .Lhandle_exception.
	 */
__restore_sgx_context_need_jmp_emulate:
	jmp * - REDZONE_SIZE - 8(%rsp)

	# void __restore_sgx_context_retry (sgx_context_t *uc)
	# __attribute__((noreturn))
	.global __restore_sgx_context_retry
	.type __restore_sgx_context_retry, @function
__restore_sgx_context_retry:
	movq %rdi, %rsp

	popq %rax
	popq %rcx
	popq %rdx
	popq %rbx
	addq $8, %rsp /* don't pop RSP yet */
	popq %rbp
	popq %rsi
	popq %rdi
	popq %r8
	popq %r9
	popq %r10
	popq %r11
	popq %r12
	popq %r13

	/* store saved %rip at -REDZONE-8(%saved rsp) */
	## there is sgx_context_t + xsave area + 8 bytes + redzone
	## is allocated on the stack. So it doesn't clobber saved
	## registers.
	##
	## see the definition of sgx_context_t
	## currently %rsp is pointing to %r14
	movq -10 * 8(%rsp), %r14 # %r14 = saved %rsp
	movq 3 * 8(%rsp), %r15	 # %r15 = saved %rip
	movq %r15, - REDZONE_SIZE - 8(%r14)

	popq %r14

#if 0
	movq %gs:SGX_SELF, %r15
	addq $SGX_FLAGS, %r15
	lock btrq $SGX_TLS_FLAGS_EVENT_EXECUTING_BIT, (%r15)
#else
	SGX_TLS_FLAGS_CLEAR_EXECUTING_BIT %r15
#endif
	/* There is a window from here to movq below where stack
	 * can grow. */
	lock btrq $SGX_TLS_FLAGS_ASYNC_EVENT_PENDING_BIT, (%r15)
	jc .Ltry_again

	popq %r15
	popfq

	/* In user context, sysret nor iret isn't usable.
	 * the following two instructions need to be atomic.
	 */
	movq -13 * 8(%rsp), %rsp
	/* If interrupted here,
	 * signal handler can clobber the saved rip at -REDZONE_SIZE-8(%rsp).
	 * So singla handler emulates the following jmp instruciton before
	 * using stack.
	 * see .Lhandle_exception.
	 */
__restore_sgx_context_retry_need_jmp_emulate:
	jmp * - REDZONE_SIZE - 8(%rsp)

.Ltry_again:
	lock btsq $SGX_TLS_FLAGS_EVENT_EXECUTING_BIT, (%r15)
	subq $15 * 8, %rsp 	# revert popq
	movq %rsp, %rdi
	callq _DkExceptionHandlerMore

	# void save_xregs(uint64_t xsave_area)
	.global save_xregs
	.type save_xregs, @function
save_xregs:
	fwait
	movq xsave_enabled@GOTPCREL(%rip), %rax
	movl (%rax), %eax
	cmpl $0, %eax
	jz 1f

	## clear xsave header
	movq $0, XSAVE_HEADER_OFFSET + 0 * 8(%rdi)
	movq $0, XSAVE_HEADER_OFFSET + 1 * 8(%rdi)
	movq $0, XSAVE_HEADER_OFFSET + 2 * 8(%rdi)
	movq $0, XSAVE_HEADER_OFFSET + 3 * 8(%rdi)
	movq $0, XSAVE_HEADER_OFFSET + 4 * 8(%rdi)
	movq $0, XSAVE_HEADER_OFFSET + 5 * 8(%rdi)
	movq $0, XSAVE_HEADER_OFFSET + 6 * 8(%rdi)
	movq $0, XSAVE_HEADER_OFFSET + 7 * 8(%rdi)

	movl $0xffffffff, %eax
	movl $0xffffffff, %edx
	xsave64 (%rdi)
	retq
1:
	fxsave64 (%rdi)
	retq


	# void restore_xregs(uint64_t xsave_area)
	.global restore_xregs
	.type restore_xregs, @function
restore_xregs:
	movq xsave_enabled@GOTPCREL(%rip), %rax
	movl (%rax), %eax
	cmpl $0, %eax
	jz 1f

	movl $0xffffffff, %eax
	movl $0xffffffff, %edx
	xrstor64 (%rdi)
	retq
1:
	fxrstor64 (%rdi)
	retq
