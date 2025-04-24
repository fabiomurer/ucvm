
#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <signal.h>

#include "utils.h"
#include "view_linux.h"
#include "syscall.h"

// https://github.com/danteu/novdso
void remove_vdso(int pid)
{
	u_int64_t val = 0;

	// get rsp value, rsp is at the start of stack because program is just
	// sarted execution
	errno = 0; // clear errno
	size_t pos = (size_t)ptrace(PTRACE_PEEKUSER, pid, WORDLEN * RSP, NULL);
	if (errno != 0) {
		PANIC_PERROR("ptrace(PTRACE_PEEKUSER)");
	}

	// go to the auxiliary vector, auxvt start after two nulls
	int zeroCount = 0;
	while (zeroCount < 2) {
		errno = 0; // clear errno
		val = ptrace(PTRACE_PEEKDATA, pid, pos += WORDLEN, NULL);
		if (errno != 0) {
			PANIC_PERROR("ptrace(PTRACE_PEEKDATA)");
		}

		if (val == AT_NULL) {
			zeroCount++;
		}
	}

	// search the auxiliary vector for AT_SYSINFO_EHDR
	errno = 0; // clear errno
	val = ptrace(PTRACE_PEEKDATA, pid, pos += WORDLEN, NULL);
	if (errno != 0) {
		PANIC_PERROR("ptrace(PTRACE_PEEKDATA)");
	}

	while (true) {
		if (val == AT_NULL) {
			// auxiliary vector end
			break;
		}
		if (val == AT_SYSINFO_EHDR) {
			// found it, make it invalid
			if (ptrace(PTRACE_POKEDATA, pid, pos, AT_IGNORE) == -1)
				PANIC_PERROR("ptrace(PTRACE_POKEDATA)");
			break;
		}

		errno = 0; // clear errno
		val = ptrace(PTRACE_PEEKDATA, pid, pos += sizeof(Elf64_auxv_t), NULL);
		if (errno != 0)
			PANIC_PERROR("ptrace(PTRACE_PEEKDATA)");
	}
}

void linux_view_worker_init(char **argv)
{
	// Ensure child dies if parent dies
	if (prctl(PR_SET_PDEATHSIG, SIGKILL) == -1) {
		PANIC_PERROR("prctl(PR_SET_PDEATHSIG)");
	}
	// check if parent died between fork and here
	if (getppid() == 1) {
		// Parent died too quickly
		_exit(1);
	}

	// Child process: request tracing and stop itself so the parent
	// can attach.
	if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
		PANIC_PERROR("ptrace(PTRACE_TRACEME)");
	}
	// Stop so the parent can set options.
	raise(SIGSTOP);

	// disable address randomization
	if (personality(ADDR_NO_RANDOMIZE) == -1) {
		PANIC_PERROR("personality(ADDR_NO_RANDOMIZE)");
	}

	// Replace the child process with the target program.
	// Note: We pass argv[0] as the program and &argv[0] as its
	// arguments.
	execvp(argv[0], &argv[0]);
	perror("execvp");
	exit(EXIT_FAILURE);
}

void linux_view_manager_init(pid_t child, struct linux_view *linux_view)
{
	int status = 0;
	// Parent process.
	// Wait for child to stop (due to SIGSTOP from the child).
	if (waitpid(child, &status, 0) == -1) {
		PANIC_PERROR("waitpid");
	}

	if (!WIFSTOPPED(status)) {
		PANIC("Child did not stop as expected.");
	}

	// Set options to catch exec event.
	if (ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACEEXEC) == -1) {
		PANIC_PERROR("ptrace(PTRACE_SETOPTIONS)");
	}

	// Resume the child process. It will now execute until the exec
	// call.
	if (ptrace(PTRACE_CONT, child, 0, 0) == -1) {
		PANIC_PERROR("ptrace(PTRACE_CONT)");
	}

	// Wait for the child to hit the exec event.
	if (waitpid(child, &status, 0) == -1) {
		PANIC_PERROR("waitpid");
	}

	// Check if this stop is due to the exec event.
	if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP &&
	    (status >> 16) == PTRACE_EVENT_EXEC) {
#ifdef DEBUG
		printf("process with pid: %d is loaded and stopped\n", child);
#endif

		// disable VDSO
		remove_vdso(child);
		linux_view->pid = child;
	} else {
		PANIC("Unexpected stop before exec event occurred.");
	}
}

void create_linux_view(char **argv, struct linux_view *linux_view)
{
	pid_t child = fork();

	if (child == -1) {
		PANIC_PERROR("fork");
	}

	if (child == 0) {
		linux_view_worker_init(argv);
	} else {
		linux_view_manager_init(child, linux_view);
	}
}


void linux_view_get_regs(struct linux_view* view, struct user_regs_struct* regs)
{
	if (ptrace(PTRACE_GETREGS, view->pid, 0, &regs) < 0) {
		PANIC_PERROR("ptrace(PTRACE_GETREGS)");
	}
}


uint64_t linux_view_do_syscall(struct linux_view* view, uint64_t nr, uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5)
{
	struct user_regs_struct regs, saved_regs;

    // 1. Get registers
    if (ptrace(PTRACE_GETREGS, view->pid, 0, &regs) < 0) {
		PANIC_PERROR("ptrace(PTRACE_GETREGS)");
	}
    saved_regs = regs;

    // 2. Save RIP
    const uint64_t rip = regs.rip;

    // 3. Write syscall instruction at RIP (2 bytes: 0x0f05, little endian)
    uint64_t patched_ins = (uint64_t)0x0f05;
    if (ptrace(PTRACE_POKETEXT, view->pid, rip, patched_ins) < 0) {
		PANIC_PERROR("ptrace(PTRACE_POKETEXT)");
	}

    // 4. Setup registers for mmap syscall
    regs.rax = nr;
    regs.rdi = arg0;
    regs.rsi = arg1;
    regs.rdx = arg2;
    regs.r10 = arg3;
    regs.r8  = arg4;
    regs.r9  = arg5;

    if (ptrace(PTRACE_SETREGS, view->pid, 0, &regs) < 0) {
		PANIC_PERROR("ptrace(PTRACE_SETREGS)");
	}

    // 5. Single-step to execute syscall instruction
    if (ptrace(PTRACE_SINGLESTEP, view->pid, 0, 0) < 0) {
		PANIC_PERROR("ptrace(PTRACE_SINGLESTEP)");
	}
    waitpid(view->pid, nullptr, 0);

    // 6. Read registers to get return value
    if (ptrace(PTRACE_GETREGS, view->pid, 0, &regs) < 0) {
		PANIC_PERROR("ptrace(PTRACE_GETREGS)");
	}
	uint64_t ret = regs.rax;

    // 7. Restore original registers
	if (ptrace(PTRACE_SETREGS, view->pid, 0, &saved_regs) < 0) {
		PANIC_PERROR("ptrace(PTRACE_SETREGS)");
	}

	return ret;
}
