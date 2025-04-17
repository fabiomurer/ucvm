
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
#include "load_linux.h"
#include "syscall.h"

struct linux_proc_info {
	pid_t pid;			/* process id */
	char tcomm[512];		/* filename of the executable */
	char state;			/* process state (R, S, D, Z, T) */
	pid_t ppid;			/* process id of the parent process */
	pid_t pgrp;			/* pgrp of the process */
	pid_t sid;			/* session id */
	int tty_nr;			/* tty the process uses */
	int tty_pgrp;			/* pgrp of the tty */
	unsigned long flags;		/* task flags */
	unsigned long min_flt;		/* number of minor faults */
	unsigned long cmin_flt;		/* number of minor faults with child’s */
	unsigned long maj_flt;		/* number of major faults */
	unsigned long cmaj_flt;		/* number of major faults with child’s */
	unsigned long utime;		/* user mode jiffies */
	unsigned long stime;		/* kernel mode jiffies */
	long cutime;			/* user mode jiffies with child’s */
	long cstime;			/* kernel mode jiffies with child’s */
	long priority;			/* priority level */
	long nice;			/* nice level */
	long num_threads;		/* number of threads */
	long it_real_value;		/* (obsolete, always 0) */
	unsigned long long start_time;	/* time the process started after system
					   boot */
	unsigned long vsize;		/* virtual memory size */
	long rss;			/* resident set memory size */
	unsigned long rsslim;		/* current limit in bytes on the rss */
	unsigned long start_code;	/* address above which program text can run */
	unsigned long end_code;		/* address below which program text can run */
	unsigned long start_stack;	/* address of the start of the main process
					   stack */
	unsigned long esp;		/* current value of ESP */
	unsigned long eip;		/* current value of EIP */
	unsigned long pending;		/* bitmap of pending signals */
	unsigned long blocked;		/* bitmap of blocked signals */
	unsigned long sigign;		/* bitmap of ignored signals */
	unsigned long sigcatch;		/* bitmap of caught signals */
	unsigned long dummy1;		/* placeholder (used to be the wchan address) */
	unsigned long dummy2;		/* placeholder */
	unsigned long dummy3;		/* placeholder */
	int exit_signal;		/* signal to send to parent thread on exit */
	int task_cpu;			/* which CPU the task is scheduled on */
	unsigned int rt_priority;	/* realtime priority */
	unsigned int policy;		/* scheduling policy */
	unsigned long long blkio_ticks; /* time spent waiting for block IO */
	unsigned long gtime;		/* guest time of the task in jiffies */
	unsigned long cgtime;		/* guest time of the task children in jiffies */
	unsigned long start_data;	/* address above which program data+bss is
					   placed */
	unsigned long end_data;		/* address below which program data+bss is
					   placed */
	unsigned long start_brk;	/* address above which program heap can be
					   expanded with brk() */
	unsigned long arg_start;	/* address above which program command line is
					   placed */
	unsigned long arg_end;		/* address below which program command line is
					   placed */
	unsigned long env_start;	/* address above which program environment is
					   placed */
	unsigned long env_end;		/* address below which program environment is
					   placed */
	int exit_code;			/* the thread’s exit_code in the form reported by the
					   waitpid system call */
};

int read_proc_info(int pid, struct linux_proc_info *proc_info)
{
	char stat_path[256];
	snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);

	// Obtain the file size using stat
	struct stat st;
	if (stat(stat_path, &st) < 0) {
		PANIC_PERROR("stat");
	}
	// Many /proc files report 0 as the size; use a fallback if necessary.
	size_t file_size = st.st_size;
	if (file_size == 0) {
		file_size = 1024;
	}

	// Allocate buffer based on file size
	char *buffer = malloc(file_size + 1);
	if (buffer == NULL)
		PANIC_PERROR("malloc");

	FILE *fp = fopen(stat_path, "r");
	if (fp == NULL)
		PANIC_PERROR("fopen");

	// Read the file into the buffer
	size_t bytes_read = fread(buffer, 1, file_size, fp);
	if (bytes_read == 0)
		PANIC_PERROR("fread");

	buffer[bytes_read] = '\0'; // Null-terminate the string
	fclose(fp);

	// There are 52 fields in /proc/[pid]/stat.
	// Note: The second field (tcomm) is enclosed in parentheses and may
	// contain spaces.
	int ret = sscanf(buffer,
			 "%d "	 /* pid */
			 "%s "	 /* tcomm: read until ')' */
			 "%c "	 /* state */
			 "%d "	 /* ppid */
			 "%d "	 /* pgrp */
			 "%d "	 /* sid */
			 "%d "	 /* tty_nr */
			 "%d "	 /* tty_pgrp */
			 "%lu "	 /* flags */
			 "%lu "	 /* min_flt */
			 "%lu "	 /* cmin_flt */
			 "%lu "	 /* maj_flt */
			 "%lu "	 /* cmaj_flt */
			 "%lu "	 /* utime */
			 "%lu "	 /* stime */
			 "%ld "	 /* cutime */
			 "%ld "	 /* cstime */
			 "%ld "	 /* priority */
			 "%ld "	 /* nice */
			 "%ld "	 /* num_threads */
			 "%ld "	 /* it_real_value */
			 "%llu " /* start_time */
			 "%lu "	 /* vsize */
			 "%ld "	 /* rss */
			 "%lu "	 /* rsslim */
			 "%lu "	 /* start_code */
			 "%lu "	 /* end_code */
			 "%lu "	 /* start_stack */
			 "%lu "	 /* esp (kstkesp) */
			 "%lu "	 /* eip (kstkeip) */
			 "%lu "	 /* pending (signal) */
			 "%lu "	 /* blocked */
			 "%lu "	 /* sigign (sigignore) */
			 "%lu "	 /* sigcatch */
			 "%lu "	 /* dummy1 (wchan) */
			 "%lu "	 /* dummy2 (nswap) */
			 "%lu "	 /* dummy3 (cnswap) */
			 "%d "	 /* exit_signal */
			 "%d "	 /* task_cpu (processor) */
			 "%u "	 /* rt_priority */
			 "%u "	 /* policy */
			 "%llu " /* blkio_ticks */
			 "%lu "	 /* gtime (guest_time) */
			 "%lu "	 /* cgtime (cguest_time) */
			 "%lu "	 /* start_data */
			 "%lu "	 /* end_data */
			 "%lu "	 /* start_brk */
			 "%lu "	 /* arg_start */
			 "%lu "	 /* arg_end */
			 "%lu "	 /* env_start */
			 "%lu "	 /* env_end */
			 "%d",	 /* exit_code */
			 &proc_info->pid, proc_info->tcomm, &proc_info->state, &proc_info->ppid,
			 &proc_info->pgrp, &proc_info->sid, &proc_info->tty_nr,
			 &proc_info->tty_pgrp, &proc_info->flags, &proc_info->min_flt,
			 &proc_info->cmin_flt, &proc_info->maj_flt, &proc_info->cmaj_flt,
			 &proc_info->utime, &proc_info->stime, &proc_info->cutime,
			 &proc_info->cstime, &proc_info->priority, &proc_info->nice,
			 &proc_info->num_threads, &proc_info->it_real_value, &proc_info->start_time,
			 &proc_info->vsize, &proc_info->rss, &proc_info->rsslim,
			 &proc_info->start_code, &proc_info->end_code, &proc_info->start_stack,
			 &proc_info->esp, &proc_info->eip, &proc_info->pending, &proc_info->blocked,
			 &proc_info->sigign, &proc_info->sigcatch, &proc_info->dummy1,
			 &proc_info->dummy2, &proc_info->dummy3, &proc_info->exit_signal,
			 &proc_info->task_cpu, &proc_info->rt_priority, &proc_info->policy,
			 &proc_info->blkio_ticks, &proc_info->gtime, &proc_info->cgtime,
			 &proc_info->start_data, &proc_info->end_data, &proc_info->start_brk,
			 &proc_info->arg_start, &proc_info->arg_end, &proc_info->env_start,
			 &proc_info->env_end, &proc_info->exit_code);

	if (ret != 52) {
		PANIC("sscanf");
	}

	free(buffer);

	return 0;
}

// https://github.com/danteu/novdso
void remove_vdso(int pid)
{
	u_int64_t val;

	// get rsp value, rsp is at the start of stack because program is just
	// sarted execution
	errno = 0; // clear errno
	size_t pos = (size_t)ptrace(PTRACE_PEEKUSER, pid, WORDLEN * RSP, NULL);
	if (errno != 0)
		PANIC_PERROR("ptrace(PTRACE_PEEKUSER)");

	// go to the auxiliary vector, auxvt start after two nulls
	int zeroCount = 0;
	while (zeroCount < 2) {
		errno = 0; // clear errno
		val = ptrace(PTRACE_PEEKDATA, pid, pos += WORDLEN, NULL);
		if (errno != 0)
			PANIC_PERROR("ptrace(PTRACE_PEEKDATA)");

		if (val == AT_NULL)
			zeroCount++;
	}

	// search the auxiliary vector for AT_SYSINFO_EHDR
	errno = 0; // clear errno
	val = ptrace(PTRACE_PEEKDATA, pid, pos += WORDLEN, NULL);
	if (errno != 0)
		PANIC_PERROR("ptrace(PTRACE_PEEKDATA)");

	while (true) {
		if (val == AT_NULL)
			// auxiliary vector end
			break;
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

void load_linux(char **argv, struct linux_proc *linux_proc)
{
	int status = 0;
	pid_t child = fork();

	if (child == -1) {
		PANIC_PERROR("fork");
	}

	if (child == 0) {
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
	} else {
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

			struct linux_proc_info proc_info = { 0 };
			read_proc_info(child, &proc_info);
			uint64_t brk = proc_info.start_brk;

			struct user_regs_struct user_regs;
			if (ptrace(PTRACE_GETREGS, child, NULL, &user_regs) == -1) {
				PANIC_PERROR("ptrace(PTRACE_GETREGS)");
			}

			linux_proc->pid = child;
			linux_proc->brk = brk;
			linux_proc->rip = user_regs.rip;
			linux_proc->rsp = user_regs.rsp;
		} else {
			PANIC("Unexpected stop before exec event occurred.");
		}
	}
}
