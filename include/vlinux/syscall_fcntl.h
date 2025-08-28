#pragma once
#include <stdint.h>

uint64_t syscall_fcntl(uint64_t fd, uint64_t cmd, uint64_t arg);
