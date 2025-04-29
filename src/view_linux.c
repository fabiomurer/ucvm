#define _GNU_SOURCE
#include <elf.h>
#include <linux/limits.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <syscall.h>
#include <fcntl.h>

#include "utils.h"
#include "view_linux.h"
#include "vsyscall.h"

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
			if (ptrace(PTRACE_POKEDATA, pid, pos, AT_IGNORE) == -1) {
				PANIC_PERROR("ptrace(PTRACE_POKEDATA)");
			}
			break;
		}

		errno = 0; // clear errno
		val = ptrace(PTRACE_PEEKDATA, pid, pos += sizeof(Elf64_auxv_t), NULL);
		if (errno != 0) {
			PANIC_PERROR("ptrace(PTRACE_PEEKDATA)");
		}
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
		PANIC("linux_view_worker is dead");
	}

	// Child process: request tracing and stop itself so the parent
	// can attach.
	if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
		PANIC_PERROR("ptrace(PTRACE_TRACEME)");
	}
	// Stop so the parent can set options.
	if (raise(SIGSTOP) < 0) {
		PANIC_PERROR("raise");
	}

	// disable address randomization
	if (personality(ADDR_NO_RANDOMIZE) == -1) {
		PANIC_PERROR("personality(ADDR_NO_RANDOMIZE)");
	}

	execvp(argv[0], &argv[0]);
	perror("execvp");
	exit(EXIT_FAILURE);
}

int open_proc_mem(pid_t pid)
{
	char mem_path[PATH_MAX];
	int memfd = -1;

	int path_len = snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

	if (path_len < 0 || (size_t)path_len >= sizeof(mem_path)) {
		return -1;
	}

	memfd = open(mem_path, O_RDWR);

	if (memfd == -1) {
		return -1;
	}

	return memfd;
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
	    (status >> 16) != PTRACE_EVENT_EXEC) {
		PANIC("Unexpected stop before exec event occurred.");
	}

	// Single-step: after PTRACE_EVENT_EXEC a PTRACE_SINGLESTEP (maybe) is required to step
	// into the program. RIP does't change ater it so i assume that no assemby is runned.
	if (ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0) {
		PANIC_PERROR("ptrace(PTRACE_SINGLESTEP)");
	}
	waitpid(child, nullptr, 0);

#ifdef DEBUG
	printf("process with pid: %d is loaded and stopped\n", child);
#endif

	// disable VDSO
	remove_vdso(child);

	linux_view->pid = child;

	// open the memory file
	linux_view->memfd = open_proc_mem(child);
	if (linux_view->memfd < 0) {
		PANIC("open_proc_mem");
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

	linux_view->argv = argv;
}

void linux_view_get_regs(struct linux_view *view, struct user_regs_struct *regs)
{
	if (ptrace(PTRACE_GETREGS, view->pid, 0, regs) < 0) {
		PANIC_PERROR("ptrace(PTRACE_GETREGS)");
	}
}

int linux_view_read_mem(struct linux_view *view, off64_t src, void *dest, size_t len)
{
	ssize_t nread = pread64(view->memfd, dest, len, src);

	// has to read exact number of byte
	if ((size_t)nread != len) {
		return -1;
	}

	return 0;
}

off64_t linux_view_alloc_mem(struct linux_view *view, size_t size)
{
	uint64_t ret = linux_view_do_syscall(view, __NR_mmap,
					     0, // null
					     size, PROT_READ | PROT_WRITE,
					     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if ((void *)ret == MAP_FAILED) {
		PANIC("linux_view_do_syscall(__NR_mmap)");
	}

	return (off64_t)ret;
}

void linux_view_free_mem(struct linux_view *view, off64_t addr, size_t size)
{
	uint64_t ret = linux_view_do_syscall(view, __NR_munmap, addr, size, 0, 0, 0, 0);

	if (ret == (uint64_t)-1) {
		PANIC("linux_view_do_syscall(__NR_munmap)");
	}
}

int linux_view_write_mem(struct linux_view *view, off64_t dest, const void *src, size_t len)
{
	if (len == 0) {
		return 0;
	}

	ssize_t nwritten = pwrite64(view->memfd, src, len, dest);

	if (nwritten != (ssize_t)len) {
		return -1;
	}

	return 0;
}

uint64_t linux_view_do_syscall(struct linux_view *view, uint64_t nr, uint64_t arg0, uint64_t arg1,
			       uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5)
{
	struct user_regs_struct regs;
	struct user_regs_struct saved_regs;

	if (ptrace(PTRACE_GETREGS, view->pid, 0, &regs) < 0) {
		PANIC_PERROR("ptrace(PTRACE_GETREGS)");
	}
	saved_regs = regs;

	// 2. Save RIP
	uint64_t saved_rip = regs.rip;

	// save instruction
	errno = 0;
	uint64_t saved_inst = ptrace(PTRACE_PEEKTEXT, view->pid, saved_rip, 0);
	if (errno != 0) {
		PANIC_PERROR("ptrace(PTRACE_PEEKTEXT)");
	}

	// Write syscall instruction at RIP
	uint64_t patched_ins = (uint64_t)SYSCALL_OPCODE_REV;
	if (ptrace(PTRACE_POKETEXT, view->pid, saved_rip, patched_ins) < 0) {
		PANIC_PERROR("ptrace(PTRACE_POKETEXT)");
	}

	// set syscall arguments
	regs.rax = nr;
	regs.rdi = arg0;
	regs.rsi = arg1;
	regs.rdx = arg2;
	regs.r10 = arg3;
	regs.r8 = arg4;
	regs.r9 = arg5;

	if (ptrace(PTRACE_SETREGS, view->pid, 0, &regs) < 0) {
		PANIC_PERROR("ptrace(PTRACE_SETREGS)");
	}

	// Single-step to execute syscall instruction
	if (ptrace(PTRACE_SINGLESTEP, view->pid, 0, 0) < 0) {
		PANIC_PERROR("ptrace(PTRACE_SINGLESTEP)");
	}
	waitpid(view->pid, nullptr, 0);

	// Read registers to get return value
	if (ptrace(PTRACE_GETREGS, view->pid, 0, &regs) < 0) {
		PANIC_PERROR("ptrace(PTRACE_GETREGS)");
	}
	uint64_t ret = regs.rax;

	// Restore original registers
	if (ptrace(PTRACE_SETREGS, view->pid, 0, &saved_regs) < 0) {
		PANIC_PERROR("ptrace(PTRACE_SETREGS)");
	}

	// restore inst
	if (ptrace(PTRACE_POKETEXT, view->pid, saved_rip, saved_inst) < 0) {
		PANIC_PERROR("ptrace(PTRACE_POKETEXT)");
	}

	return ret;
}
