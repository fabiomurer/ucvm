#pragma once
#define _GNU_SOURCE

#include "vm.h"

uint64_t syscall_fstat(struct vm *vm, int fd, uint64_t statbuf);
