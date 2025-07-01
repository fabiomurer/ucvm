#pragma once
#define _GNU_SOURCE
#include <stdint.h>

uint64_t vlinux_syscall_exit_group(int status);
