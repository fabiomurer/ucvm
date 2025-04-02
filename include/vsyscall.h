#pragma once

#include <linux/kvm.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "load_linux.h"
#include "vm.h"

#define SYSCALL_OPCODE 0x0F05
#define SYSCALL_OP_SIZE 2

bool is_syscall(struct vm *vm, struct kvm_regs *regs);

uint64_t syscall_handler(struct vm *vm, struct linux_proc *linux_proc, struct kvm_regs *regs);
