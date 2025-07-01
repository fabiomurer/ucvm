#pragma once
#define _GNU_SOURCE

#include "vm.h"

uint64_t vlinux_syscall_open(struct vm *vm, uint64_t filename, int flags, mode_t mode);
