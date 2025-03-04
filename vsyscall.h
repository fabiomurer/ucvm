#pragma once 

#include <stdbool.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <sys/types.h>

#include "vm.h"
#include "load_linux.h"

#define SYSCALL_OPCODE 0x0F05
#define SYSCALL_OP_SIZE 2

void* vm_guest_to_host(struct vm* vm, u_int64_t guest_addr);

bool is_syscall(struct vm* vm, struct kvm_regs* regs);

uint64_t syscall_handler(struct vm* vm, struct linux_proc* linux_proc, struct kvm_regs* regs);