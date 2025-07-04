#pragma once
#define _GNU_SOURCE

#include "vm.h"

uint64_t syscall_pread64(struct vm *vm, int fd, uint64_t buf, size_t count, off_t offset);
