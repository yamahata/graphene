#include "pal_linux_defs.h"
#include "sgx_arch.h"

#include "asm-offsets.h"

	.extern tcs_base

	.global sgx_ecall
	.type sgx_ecall, @function

sgx_ecall:
	# put entry address in RDX
	leaq sgx_entry(%rip), %rdx

	# other arguments: RDI - code, RSI - ms

.Ldo_ecall:
	# RBX has to be the TCS of the thread
	movq current_tcs@gottpoff(%rip), %rbx
	movq %fs:(%rbx), %rbx

	# RCX has to be the AEP (Asynchronous Exit Pointer)
	leaq async_exit_pointer(%rip), %rcx

	movq $EENTER, %rax
	ENCLU

	.global async_exit_pointer
	.type async_exit_pointer, @function

async_exit_pointer:
	ENCLU

	.global sgx_raise
	.type sgx_raise, @function

sgx_raise:
	leaq .Lafter_resume(%rip), %rdx
	jmp .Ldo_ecall

.Lafter_resume:
	retq

sgx_entry:
	# arguments: RDI - code, RSI - ms

	leaq ocall_table(%rip), %rbx
	movq (%rbx,%rdi,8), %rbx
	movq %rsi, %rdi
	movq %rsp, %r12
	andq $~15, %rsp
	callq *%rbx
	movq %r12, %rsp

	movq %rax, %rdi
	# Not interrupted
	xorq %rsi, %rsi

	.global sgx_entry_return
	.type sgx_entry_return, @function

sgx_entry_return:
	# return to enclave, arguments:
	# RDI - return value
	# RSI - external event
	jmp .Ldo_ecall
