#include <linux/kvm.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>

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


uint64_t syscall_handler(struct vm* vm, struct linux_proc* linux_proc, struct kvm_regs* regs) {
	uint64_t sysno = regs->rax;
	uint64_t arg1 = regs->rdi;
	uint64_t arg2 = regs->rsi;
	uint64_t arg3 = regs->rdx;
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

		default:
			printf("ENOSYS, syscall number %d\n", (int)sysno);
			ret = -ENOSYS;
			sysno = ENOSYS; // return syscall not recognised
	}
	regs->rax = ret;
	return sysno;
}