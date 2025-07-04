#pragma once
#define _GNU_SOURCE
#include <stdint.h>
#include <sys/types.h>

#include "vm.h"

uint64_t syscall_openat(struct vm *vm, int dirfd, uint64_t filename, int flags, mode_t mode);
