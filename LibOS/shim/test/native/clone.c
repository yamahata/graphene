/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#define _GNU_SOURCE
#include <malloc.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <sched.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <asm/prctl.h>

// 64kB stack
#define FIBER_STACK 1024 * 64

__thread int mypid = 0;

unsigned long gettls (void)
{
    unsigned long tls;
    syscall(__NR_arch_prctl, ARCH_GET_FS, &tls);
    return tls;
}

int thread_function (void * argument)
{
    mypid = getpid();
    int * ptr = (int *) argument;
    printf("ptr: argument passed %p\n", ptr);
    fflush(stdout);
    printf("in the child: pid (%016lx) = %d\n", (unsigned long) &mypid, mypid);
    fflush(stdout);
    printf("in the child: pid = %d\n", getpid());
    fflush(stdout);
    printf("in the child: tls = %08lx\n", gettls());
    fflush(stdout);
    printf("child thread exiting\n");
    fflush(stdout);
    printf("argument passed %p\n", ptr);
    fflush(stdout);
    printf("argument passed %d\n", *ptr);
    fflush(stdout);
    return 0;
}

int main (int argc, const char ** argv)
{
    void * stack;
    pid_t pid;
    int varx = 143;

    mypid = getpid();

    printf("in the parent: pid = %d\n", getpid());

    // Allocate the stack
    stack = malloc(FIBER_STACK);
    if (stack == 0) {
        perror("malloc: could not allocate stack");
        _exit(1);
    }

    printf("child_stack: %016lx-%016lx\n", (unsigned long) stack,
           (unsigned long) stack + FIBER_STACK);

    printf("&varx: %p\n", &varx);
    fflush(stdout);

    // Call the clone system call to create the child thread
    pid = clone(&thread_function, (void *) stack + FIBER_STACK,
                CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_VM,
                &varx);

    printf("clone() creates new thread %d\n", pid);
    fflush(stdout);

    if (pid == -1) {
        perror("clone");
        _exit(2);
    }

    // Wait for the child thread to exit
    pid = waitpid(0, NULL, __WALL);
    if (pid == -1) {
        perror("waitpid");
        _exit(3);
    }

    // Free the stack
    free(stack);

    printf("in the parent: pid (%016lx) = %d\n", (unsigned long) &mypid, mypid);
    fflush(stdout);
    printf("in the parent: pid = %d\n", getpid());
    fflush(stdout);
    printf("in the parent: tls = %08lx\n", gettls());
    fflush(stdout);

    return 0;
}
