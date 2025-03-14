#define _GNU_SOURCE
#include <asm/kvm.h>
#include <asm/unistd_64.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <linux/limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <linux/futex.h>
#include <asm/prctl.h>
#include <sys/resource.h>
#include <sys/random.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "vsyscall.h"
#include "utils.h"
#include "vmm.h"
#include "guest_inspector.h"
#include "arguments.h"

bool is_syscall(struct vm* vm, struct kvm_regs* regs) {

	uint8_t inst[2];
	if (read_buffer_host(vm, regs->rip, inst, sizeof(u_int8_t)*2) < 0) {
		panic("read_buffer_host");
	} 

	uint64_t rip_content = inst[1] | (inst[0] << 8);
	if (rip_content == SYSCALL_OPCODE) {
		return true;
	} else {
		return false;
	}
}

uint64_t vlinux_syscall_brk(struct linux_proc* linux_proc, uint64_t addr) {
	/*
	the actual Linux system call returns the new program
    break on success.  On failure, the system call returns the current
    break.
	*/
	if (addr == 0) {
		return linux_proc->brk;
	}

	if (addr >= linux_proc->brk) {
		u_int64_t increment = (u_int64_t)addr - linux_proc->brk;
		
		alloc_memory(linux_proc->brk, increment);
		
		linux_proc->brk += increment;
		return linux_proc->brk;
	} else {
		// shrink with brk not supported
		fprintf(stderr, "brk shrink not supported\n");
	}

	return linux_proc->brk;
}

uint64_t vlinux_syscall_arch_prctl(struct vm* vm, uint64_t op, uint64_t addr) {
	uint64_t ret = -1;
	struct kvm_sregs2 sregs;
	switch(op) {
		case ARCH_SET_FS:
			if (ioctl(vm->vcpufd, KVM_GET_SREGS2, &sregs) < 0) {
				panic("KVM_GET_SREGS2");
			}

			// set the base address of fs register to addr
			sregs.fs.base = addr;
			
			if (ioctl(vm->vcpufd, KVM_SET_SREGS2, &sregs) < 0) {
				panic("KVM_SET_SREGS2");
			}
			return 0;
		default:
			panic("vlinux_syscall_arch_prctl OP NOT SUPPORTED");
			break;
	}
	return ret;
}

#define HANDLE_SYSCALL(nr) \
    case nr: \
        if (arguments.trace_enabled) {printf(#nr "\n");}

uint64_t syscall_handler(struct vm* vm, struct linux_proc* linux_proc, struct kvm_regs* regs) {
	uint64_t sysno = regs->rax;
	uint64_t arg1 = regs->rdi;
	uint64_t arg2 = regs->rsi;
	uint64_t arg3 = regs->rdx;
	//uint64_t arg4 = regs->r10;
	//uint64_t arg5 = regs->r9;
	uint64_t ret = 0;

	switch (sysno) {
		HANDLE_SYSCALL(__NR_write)
			int fd 			= (int)arg1;
			uint64_t buff 	= arg2;
			size_t len		= arg3;

			uint8_t* tmp_buff	= malloc(sizeof(uint8_t) * len);
			if (read_buffer_host(vm, buff, tmp_buff, len) < 0) {
				panic("read_buffer_host");
			}

			ret = write((int)arg1, tmp_buff, arg3);
			if (ret == (u_int64_t)-1) {
				perror("__NR_write");
			} else {
				printf("byte written: %lu\n", ret);
			}
			free(tmp_buff);
			break;

		HANDLE_SYSCALL(__NR_fstat)
			fd = (int)arg1;
			uint64_t statbuf = arg2;
			struct stat tmp_statbuf;

			if (fstat(fd, &tmp_statbuf) < 0) {
				ret = -errno;
			} else {
				if (write_buffer_guest(vm, statbuf, (uint8_t*)&tmp_statbuf, sizeof(tmp_statbuf)) < 0) {
					panic("write_buffer_guest");
				}
			}
			break;

		HANDLE_SYSCALL(__NR_mprotect)
			break;

		HANDLE_SYSCALL(__NR_brk)
			ret = vlinux_syscall_brk(linux_proc, arg1);
			break;

		HANDLE_SYSCALL(__NR_exit)
			_exit(arg1);
			break;
		
		HANDLE_SYSCALL(__NR_arch_prctl)
			ret = vlinux_syscall_arch_prctl(vm, arg1, arg2);
			break;

		HANDLE_SYSCALL(__NR_set_tid_address)
			/*
			The system call set_tid_address() sets the clear_child_tid value
			for the calling thread to tidptr.
			*/
			linux_proc->clear_child_tid = arg1;

			/*
			set_tid_address() always returns the caller's thread ID.
			for now 1 thread -> thread ID = 0
			*/
			ret = 0;
			break;

		HANDLE_SYSCALL(__NR_exit_group)
			int status = (int)arg1;
			syscall(SYS_exit_group, status);
			break;

		HANDLE_SYSCALL(__NR_readlinkat)
			char pathname[PATH_MAX];
			if (read_string_host(vm, arg2, pathname, PATH_MAX) < 0) {
				panic("read_string_host");
			}
			int dirfd = (int)arg1;

			// support only get process path
			if (strcmp("/proc/self/exe", pathname) == 0 && dirfd == AT_FDCWD) {
				char buf[PATH_MAX] = "\0";
				if (realpath(linux_proc->argv[0], buf) == NULL) {
					panic("realpath");
				}
				ret = strlen(buf);

				if (write_string_guest(vm, arg3, buf, PATH_MAX) < 0) {
					panic("write_string_guest");
				}
				printf("%s\n", buf);
			} else {
				panic("__NR_readlinkat case not supported");
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
				linux_proc->robust_list_head_ptr = arg1;
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
				panic("__NR_prlimit64 case not supported");
			}
			break;

		HANDLE_SYSCALL(__NR_getrandom)
			uint64_t buf = arg1;
			size_t buflen = arg2;
			unsigned int flags = arg3;

			uint8_t* tbuf = malloc(buflen * sizeof(char));
			if (tbuf == NULL) panic("malloc");

			ret = getrandom(tbuf, buflen, flags);
			if (write_buffer_guest(vm, buf, tbuf, buflen) < 0) {
				panic("write_buffer_guest");
			}

			free(tbuf);
			break;

		
		// https://manpages.opensuse.org/Tumbleweed/librseq-devel/rseq.2.en.html
		HANDLE_SYSCALL(__NR_rseq) // what is this?? not implemented -> hopefully not used
			ret = 0;
			break;

		default:
			printf("ENOSYS, syscall number %d\n", (int)sysno);
			ret = -ENOSYS;
			sysno = ENOSYS; // return syscall not recognised
	}
	regs->rax = ret;
	return sysno;
}
