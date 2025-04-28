#pragma once

#define _GNU_SOURCE

#include "vm.h"

#define SYSCALL_OPCODE 0x0F05
#define SYSCALL_OPCODE_REV 0x050F
#define SYSCALL_OP_SIZE 2

uint64_t syscall_handler(struct vm *vm, struct kvm_regs *regs);
