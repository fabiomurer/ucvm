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

#include "vsyscall.h"
#include "utils.h"
#include "vmm.h"


void* vm_guest_to_host(struct vm* vm, u_int64_t guest_addr) {
	struct kvm_translation transl_addr;
	transl_addr.linear_address = guest_addr;

	if (ioctl(vm->vcpufd, KVM_TRANSLATE, &transl_addr) < 0) {
		panic("KVM_TRANSLATE");
	}

	if (transl_addr.valid == 0) {
		fprintf(stderr, "KVM_TRANSLATE not valid\n");
		exit(EXIT_FAILURE);
	}

	return (void*)((uint64_t)vm->memory + transl_addr.physical_address - GUEST_PHYS_ADDR);
}

void read_string_host(struct vm* vm, uint64_t guest_string_addr, char* buf, size_t bufsiz) {
	size_t byte_read = 0;
	char* host_addr = NULL;

	memset(buf, 0, bufsiz);
	do {
		host_addr = vm_guest_to_host(vm, guest_string_addr + byte_read);
		buf[byte_read] = *host_addr;
		byte_read++;
	} while (byte_read < bufsiz && *host_addr != '\0');
}

void write_string_guest(struct vm* vm, uint64_t guest_string_addr, char* buf, size_t bufsiz) {
	size_t byte_written = 0;
	char* host_addr = NULL;

	do {
		host_addr = vm_guest_to_host(vm, guest_string_addr + byte_written);
		*host_addr = buf[byte_written];
		byte_written++;
	} while (byte_written < bufsiz && buf[byte_written] != '\0');

	if (byte_written+1 < bufsiz) {
		byte_written++;
		host_addr = vm_guest_to_host(vm, guest_string_addr + byte_written);
		*host_addr = '\0';
	}
}

void write_buffer_guest(struct vm* vm, uint64_t guest_buffer_addr, char* buf, size_t bufsiz) {
	size_t byte_written = 0;
	char* host_addr = NULL;

	do {
		host_addr = vm_guest_to_host(vm, guest_buffer_addr + byte_written);
		*host_addr = buf[byte_written];
		byte_written++;
	} while (byte_written < bufsiz);
}

bool is_syscall(struct vm* vm, struct kvm_regs* regs) {

	uint8_t* addr = (uint8_t*)vm_guest_to_host(vm, regs->rip); 

	uint64_t rip_content = addr[1] | (addr[0] << 8);
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

uint64_t syscall_handler(struct vm* vm, struct linux_proc* linux_proc, struct kvm_regs* regs) {
	uint64_t sysno = regs->rax;
	uint64_t arg1 = regs->rdi;
	uint64_t arg2 = regs->rsi;
	uint64_t arg3 = regs->rdx;
	uint64_t arg4 = regs->r10;
	uint64_t arg5 = regs->r9;
	uint64_t ret = 0;

	switch (sysno) {
		case __NR_write:
			void* buff = vm_guest_to_host(vm, arg2);

			printf("=======__NR_write\n");
			printf("fd: %d\n", (int)arg1);
			printf("buff: %s\n", (char*)buff);
			printf("len: %lu\n", arg3);
			printf("=======\n");

			ret = write((int)arg1, (char*)buff, arg3);
			if (ret == (u_int64_t)-1) {
				perror("__NR_write");
			} else {
				printf("byte written: %lu\n", ret);
			}
			break;

		case __NR_brk:
			printf("=======__NR_brk\n");
			printf("addr: %p\n", (void*)arg1);
			printf("=======\n");
			ret = vlinux_syscall_brk(linux_proc, arg1);
			break;

		case __NR_exit:
			printf("=======__NR_exit\n");
			printf("exit code: %d\n", (int)arg1);
			printf("=======\n");
			_exit(arg1);
			break;
		
		case __NR_arch_prctl:
			printf("=======__NR_arch_prctl\n");
			printf("op: %d\n", (int)arg1);
			printf("add: %p\n", (void*)arg2);
			printf("=======\n");
			ret = vlinux_syscall_arch_prctl(vm, arg1, arg2);
			break;

		case __NR_set_tid_address:
			printf("=======__NR_set_tid_address\n");
			printf("tidptr: %p\n", (void*)arg1);
			printf("=======\n");

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

		case __NR_readlinkat:
			char pathname[PATH_MAX];
			read_string_host(vm, arg2, pathname, PATH_MAX);
			int dirfd = (int)arg1;
			printf("=======__NR_readlinkat\n");
			printf("dirfd: %d\n", dirfd);
			printf("pathname: %s\n", pathname);
			printf("bufsiz: %lu\n", arg4);
			printf("=======\n");

			// support only get process path
			if (strcmp("/proc/self/exe", pathname) == 0 && dirfd == AT_FDCWD) {
				char buf[PATH_MAX] = "\0";
				if (realpath(linux_proc->argv[0], buf) == NULL) {
					panic("realpath");
				}
				ret = strlen(buf);

				write_string_guest(vm, arg3, buf, PATH_MAX);
				printf("%s\n", buf);
			} else {
				panic("__NR_readlinkat case not supported");
				ret = -1;
			}
			break;
		
		case __NR_set_robust_list:
			printf("=======__NR_set_robust_list\n");
			printf("head_ptr: %p\n", (void*)arg1);
			printf("sizep: %lu\n", arg2);
			printf("=======\n");

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
		
		case __NR_prlimit64:
			/*
			int prlimit(pid_t pid, int resource,
                   const struct rlimit *_Nullable new_limit,
                   struct rlimit *_Nullable old_limit);

       		struct rlimit {
       		    rlim_t  rlim_cur;  //Soft limit 
       		    rlim_t  rlim_max;  // Hard limit (ceiling for rlim_cur)
       		};
			*/
			printf("=======__NR_prlimit64\n");
			printf("pid: %ld\n", arg1);
			printf("resource: %ld\n", arg2);
			printf("new_limit: %p\n", (void*)arg3);
			printf("old_limit: %p\n", (void*)arg4);
			printf("=======\n");

			if (arg1 == 0 && arg2 == RLIMIT_STACK) {
				// for vm no limit for stack-> do nothing
				ret = 0;
			} else {
				panic("__NR_prlimit64 case not supported");
			}
			break;

		case __NR_getrandom:
			uint64_t buf = arg1;
			size_t buflen = arg2;
			unsigned int flags = arg3;
			printf("=======__NR_getrandom\n");
			printf("buf: %p\n", (void*)buf);
			printf("buflen: %ld\n", buflen);
			printf("flags: 0x%d\n", flags);
			printf("=======\n");

			char* tbuf = malloc(buflen * sizeof(char));
			if (tbuf == NULL) panic("malloc");

			ret = getrandom(tbuf, buflen, flags);
			write_buffer_guest(vm, buf, tbuf, buflen);

			free(tbuf);
			break;

		
		// https://manpages.opensuse.org/Tumbleweed/librseq-devel/rseq.2.en.html
		case __NR_rseq: // what is this?? not implemented -> hopefully not used
			printf("=======__NR_rseq\n");
			printf("SYSCALL IGNORED\n");
			printf("=======\n");
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