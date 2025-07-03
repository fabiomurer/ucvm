#pragma once
#define _GNU_SOURCE

#include <stddef.h>
#include <stdint.h>

uint64_t syscall_set_robust_list(uint64_t head, size_t size);
