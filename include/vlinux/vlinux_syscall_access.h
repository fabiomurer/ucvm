#pragma once
#define _GNU_SOURCE

#include "vm.h"

uint64_t vlinux_syscall_access(struct vm *vm, uint64_t pathname, int mode);
