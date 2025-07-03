#pragma once
#define _GNU_SOURCE

#include <stdint.h>
#include "view_linux.h"
#include "vm.h"

uint64_t syscall_arch_prctl(struct vm *vm, uint64_t op, uint64_t addr);
