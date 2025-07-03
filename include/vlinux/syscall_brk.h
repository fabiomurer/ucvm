#pragma once
#define _GNU_SOURCE

#include <stdint.h>
#include "view_linux.h"

uint64_t syscall_brk(struct linux_view *linux_view, uint64_t addr);
