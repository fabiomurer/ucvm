#pragma once
#define _GNU_SOURCE

#include <unistd.h>
#include <stdint.h>

uint64_t syscall_prlimit64(pid_t pid, int resource);
