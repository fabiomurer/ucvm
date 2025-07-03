#define _GNU_SOURCE

#include <asm/kvm.h>
#include <asm/prctl.h>
#include <linux/futex.h>
#include <linux/kvm.h>
#include <linux/limits.h>
#include <stdio.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "arguments.h"
#include "guest_inspector.h"
#include "utils.h"
#include "view_linux.h"
#include "vsyscall.h"

#include "vlinux/syscall_read.h"
#include "vlinux/syscall_write.h"
#include "vlinux/syscall_open.h"
#include "vlinux/syscall_close.h"
#include "vlinux/syscall_fstat.h"
#include "vlinux/syscall_mmap.h"
#include "vlinux/syscall_munmap.h"
#include "vlinux/syscall_brk.h"
#include "vlinux/syscall_pread64.h"
#include "vlinux/syscall_access.h"
#include "vlinux/syscall_getpid.h"
#include "vlinux/syscall_exit.h"
#include "vlinux/syscall_arch_prctl.h"
#include "vlinux/syscall_set_tid_address.h"
#include "vlinux/syscall_exit_group.h"
#include "vlinux/syscall_openat.h"
#include "vlinux/syscall_readlinkat.h"
#include "vlinux/syscall_set_robust_list.h"
#include "vlinux/syscall_prlimit64.h"
#include "vlinux/syscall_getrandom.h"
#include "vlinux/syscall_rseq.h"

#define HANDLE_SYSCALL(nr)                     \
	case nr:                               \
		if (arguments.trace_enabled) { \
			printf(#nr "\n");      \
		}

uint64_t syscall_handler(struct vm *vm, struct kvm_regs *regs)
{
	uint64_t sysno = regs->rax;
	uint64_t arg1 = regs->rdi;
	uint64_t arg2 = regs->rsi;
	uint64_t arg3 = regs->rdx;
	uint64_t arg4 = regs->r10;
	uint64_t arg5 = regs->r8;
	uint64_t arg6 = regs->r9;
	uint64_t ret = 0;

	switch (sysno) {
		HANDLE_SYSCALL(__NR_read)
		{
			int fd = (int)arg1;
			uint64_t buff = arg2;
			size_t len = arg3;

			ret = syscall_read(vm, fd, buff, len);
		}
		break;

		HANDLE_SYSCALL(__NR_write)
		{
			int fd = (int)arg1;
			uint64_t buff = arg2;
			size_t len = arg3;

			ret = syscall_write(vm, fd, buff, len);
		}
		break;

		HANDLE_SYSCALL(__NR_open)
		{
			uint64_t filename = arg1;
			int flags = (int)arg2;
			mode_t mode = (mode_t)arg3;

			ret = syscall_open(vm, filename, flags, mode);
		}
		break;

		HANDLE_SYSCALL(__NR_close)
		{
			int fd = (int)arg1;

			ret = syscall_close(fd);
		}
		break;

		HANDLE_SYSCALL(__NR_fstat)
		{
			int fd = (int)arg1;
			uint64_t statbuf = arg2;

			ret = syscall_fstat(vm, fd, statbuf);
		}
		break;

		HANDLE_SYSCALL(__NR_mmap)
		{
			void *addr = (void *)arg1;
			size_t lenght = (size_t)arg2;
			int prot = (int)arg3;
			int flags = (int)arg4;
			int fd = (int)arg5;
			off_t offset = (off_t)arg6;

			ret = syscall_mmap(&vm->linux_view, addr, lenght, prot, flags, fd,
						  offset);
		}
		break;

		HANDLE_SYSCALL(__NR_mprotect) // ignored
		break;

		HANDLE_SYSCALL(__NR_munmap)
		{
			uint64_t addr = arg1;
			uint64_t len = arg2;

			ret = syscall_munmap(&vm->linux_view, addr, len);
		}
		break;

		HANDLE_SYSCALL(__NR_brk)
		{
			uint64_t addr = arg1;

			ret = syscall_brk(&vm->linux_view, addr);
		}

		break;

		HANDLE_SYSCALL(__NR_pread64)
		{
			int fd = (int)arg1;
			uint64_t buf = arg2;
			size_t count = arg3;
			off_t offset = arg4;

			ret = syscall_pread64(vm, fd, buf, count, offset);
		}
		break;

		HANDLE_SYSCALL(__NR_access)
		{
			uint64_t pathname = arg1;
			int mode = (int)arg2;

			ret = syscall_access(vm, pathname, mode);
		}
		break;

		HANDLE_SYSCALL(__NR_getpid)
		{
			ret = syscall_getpid();
		}
		break;

		HANDLE_SYSCALL(__NR_exit)
		{
			int status = (int)arg1;

			syscall_exit(status);
		}
		break;

		HANDLE_SYSCALL(__NR_arch_prctl)
		{
			uint64_t op = arg1;
			uint64_t addr = arg2;

			ret = syscall_arch_prctl(vm, op, addr);
		}
		break;

		HANDLE_SYSCALL(__NR_set_tid_address)
		{
			ret = syscall_set_tid_address();
		}
		break;

		HANDLE_SYSCALL(__NR_exit_group)
		{
			int status = (int)arg1;
			ret = syscall_exit_group(status);
		}
		break;

		HANDLE_SYSCALL(__NR_openat)
		{
			int dirfd = (int)arg1;
			uint64_t filename = arg2;
			int flags = (int)arg3;
			mode_t mode = (mode_t)arg4;

			ret = syscall_openat(vm, dirfd, filename, flags, mode);
		}
		break;

		HANDLE_SYSCALL(__NR_readlinkat)
		{
			int dirfd = (int)arg1;
			uint64_t pathname = arg2;
			uint64_t buf  = arg3;
			int bufsiz = (int)arg4;

			ret = syscall_readlinkat(vm, dirfd, pathname, buf, bufsiz);
		}
		break;

		HANDLE_SYSCALL(__NR_set_robust_list)
		{
			uint64_t head = arg1;
			size_t size = arg2;

			ret = syscall_set_robust_list(head, size);
		}
		break;

		HANDLE_SYSCALL(__NR_prlimit64)
		{
			pid_t pid = (pid_t)arg1;
			int resource =(int)arg2;

			ret = syscall_prlimit64(pid, resource);
		}
		break;

		HANDLE_SYSCALL(__NR_getrandom)
		{
			uint64_t buf = arg1;
			size_t buflen = arg2;
			unsigned int flags = arg3;

			ret = syscall_getrandom(vm, buf, buflen, flags);
		}
		break;

		HANDLE_SYSCALL(__NR_rseq)
		{
			ret = syscall_rseq();
		}
		break;

	default:
		printf("syscall num: %lld not supported\n", regs->rax);
		ret = -ENOSYS;
		sysno = ENOSYS; // return syscall not recognised
	}
	regs->rax = ret;
	return sysno;
}
