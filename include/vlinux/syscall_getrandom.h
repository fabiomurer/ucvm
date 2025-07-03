#pragma once
#define _GNU_SOURCE

#include "vm.h"

uint64_t syscall_getrandom(struct vm *vm, uint64_t buf, size_t buflen, unsigned int flags);
