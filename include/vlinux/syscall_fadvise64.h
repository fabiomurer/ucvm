#pragma once
#include <stdint.h>

uint64_t syscall_fadvise64(uint64_t fd, uint64_t offset, uint64_t len, uint64_t advice);
