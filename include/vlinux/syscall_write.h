#pragma once
#define _GNU_SOURCE

#include "vm.h"

uint64_t syscall_write(struct vm *vm, int fd, uint64_t buff, size_t len);
