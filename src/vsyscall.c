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

#include "vlinux/vlinux_syscall_read.h"
#include "vlinux/vlinux_syscall_write.h"
#include "vlinux/vlinux_syscall_open.h"
#include "vlinux/vlinux_syscall_close.h"
#include "vlinux/vlinux_syscall_fstat.h"
#include "vlinux/vlinux_syscall_mmap.h"
#include "vlinux/vlinux_syscall_munmap.h"
#include "vlinux/vlinux_syscall_brk.h"
#include "vlinux/vlinux_syscall_pread64.h"
#include "vlinux/vlinux_syscall_access.h"
#include "vlinux/vlinux_syscall_getpid.h"
#include "vlinux/vlinux_syscall_exit.h"
#include "vlinux/vlinux_syscall_set_tid_address.h"
#include "vlinux/vlinux_syscall_exit_group.h"
#include "vlinux/vlinux_syscall_openat.h"

#include "vlinux/vlinux_syscall_arch_prctl.h"

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

			ret = vlinux_syscall_read(vm, fd, buff, len);
		}
		break;

		HANDLE_SYSCALL(__NR_write)
		{
			int fd = (int)arg1;
			uint64_t buff = arg2;
			size_t len = arg3;

			ret = vlinux_syscall_write(vm, fd, buff, len);
		}
		break;

		HANDLE_SYSCALL(__NR_open)
		{
			uint64_t filename = arg1;
			int flags = (int)arg2;
			mode_t mode = (mode_t)arg3;

			ret = vlinux_syscall_open(vm, filename, flags, mode);
		}
		break;

		HANDLE_SYSCALL(__NR_close)
		{
			int fd = (int)arg1;

			ret = vlinux_syscall_close(fd);
		}
		break;

		HANDLE_SYSCALL(__NR_fstat)
		{
			int fd = (int)arg1;
			uint64_t statbuf = arg2;

			ret = vlinux_syscall_fstat(vm, fd, statbuf);
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

			ret = vlinux_syscall_mmap(&vm->linux_view, addr, lenght, prot, flags, fd,
						  offset);
		}
		break;

		HANDLE_SYSCALL(__NR_mprotect)
		break;

		HANDLE_SYSCALL(__NR_munmap)
		{
			uint64_t addr = arg1;
			uint64_t len = arg2;

			ret = vlinux_syscall_munmap(&vm->linux_view, addr, len);
		}
		break;

		HANDLE_SYSCALL(__NR_brk)
		{
			uint64_t addr = arg1;

			ret = vlinux_syscall_brk(&vm->linux_view, addr);
		}

		break;

		HANDLE_SYSCALL(__NR_pread64)
		{
			int fd = (int)arg1;
			uint64_t buf = arg2;
			size_t count = arg3;
			off_t offset = arg4;

			ret = vlinux_syscall_pread64(vm, fd, buf, count, offset);
		}
		break;

		HANDLE_SYSCALL(__NR_access)
		{
			uint64_t pathname = arg1;
			int mode = (int)arg2;

			ret = vlinux_syscall_access(vm, pathname, mode);
		}
		break;

		HANDLE_SYSCALL(__NR_getpid)
		{
			ret = vlinux_syscall_getpid();
		}
		break;

		HANDLE_SYSCALL(__NR_exit)
		{
			int status = (int)arg1;

			vlinux_syscall_exit(status);
		}
		break;

		HANDLE_SYSCALL(__NR_arch_prctl)
		{
			uint64_t op = arg1;
			uint64_t addr = arg2;

			ret = vlinux_syscall_arch_prctl(vm, op, addr);
		}
		break;

		HANDLE_SYSCALL(__NR_set_tid_address)
		{
			ret = vlinux_syscall_set_tid_address();
		}
		break;

		HANDLE_SYSCALL(__NR_exit_group)
		{
			int status = (int)arg1;
			ret = vlinux_syscall_exit_group(status);
		}
		break;

		HANDLE_SYSCALL(__NR_openat)
		{
			int dirfd = (int)arg1;
			uint64_t filename = arg2;
			int flags = (int)arg3;
			mode_t mode = (mode_t)arg4;

			ret = vlinux_syscall_openat(vm, dirfd, filename, flags, mode);
		}
		break;

		HANDLE_SYSCALL(__NR_readlinkat)
		char pathname[PATH_MAX];
		if (read_string_host(vm, arg2, pathname, PATH_MAX) < 0) {
			PANIC("read_string_host");
		}
		int dirfd = (int)arg1;

		// support only get process path
		if (strcmp("/proc/self/exe", pathname) == 0 && dirfd == AT_FDCWD) {
			char buf[PATH_MAX] = "\0";
			if (realpath(vm->linux_view.argv[0], buf) == NULL) {
				PANIC_PERROR("realpath");
			}
			ret = strlen(buf);

			if (write_string_guest(vm, arg3, buf, PATH_MAX) < 0) {
				PANIC("write_string_guest");
			}
		} else {
			PANIC("__NR_readlinkat case not supported");
			ret = -1;
		}
		break;

		HANDLE_SYSCALL(__NR_set_robust_list)
		/*
		The set_robust_list() system call requests the kernel to record
		the head of the list of robust futexes owned by the calling
		thread.  The head argument is the list head to record.  The size
		argument should be sizeof(*head).
		*/
		if (arg2 == sizeof(struct robust_list_head)) {
			// linux_proc->robust_list_head_ptr = arg1;
			ret = 0;
		} else {
			ret = -1;
		}
		break;

		HANDLE_SYSCALL(__NR_prlimit64)
		if (arg1 == 0 && arg2 == RLIMIT_STACK) {
			// for vm no limit for stack-> do nothing
			ret = 0;
		} else {
			PANIC("__NR_prlimit64 case not supported");
		}
		break;

		HANDLE_SYSCALL(__NR_getrandom)
		uint64_t buf = arg1;
		size_t buflen = arg2;
		unsigned int flags = arg3;

		uint8_t *tbuf = malloc(buflen * sizeof(char));
		if (tbuf == NULL)
			PANIC_PERROR("malloc");

		ret = getrandom(tbuf, buflen, flags);
		if (write_buffer_guest(vm, buf, tbuf, buflen) < 0) {
			PANIC("write_buffer_guest");
		}

		free(tbuf);
		break;

		// https://manpages.opensuse.org/Tumbleweed/librseq-devel/rseq.2.en.html
		HANDLE_SYSCALL(__NR_rseq) // what is this?? not implemented ->
					  // hopefully not used
		ret = 0;
		break;

	default:
		printf("syscall num: %lld not supported\n", regs->rax);
		ret = -ENOSYS;
		sysno = ENOSYS; // return syscall not recognised
	}
	regs->rax = ret;
	return sysno;
}
