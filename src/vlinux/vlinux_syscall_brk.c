#include "vlinux/vlinux_syscall_brk.h"

#include <sys/syscall.h>

uint64_t vlinux_syscall_brk(struct linux_view *linux_view, uint64_t addr)
{
	/*
	the actual Linux system call returns the new program
	break on success.  On failure, the system call returns the current
	break.
	*/
	uint64_t brk = linux_view_do_syscall(linux_view, __NR_brk, addr, 0, 0, 0, 0, 0);
	return brk;
}
