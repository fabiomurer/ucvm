#pragma once
#define _GNU_SOURCE

#include "view_linux.h"
#include "vm.h"

uint64_t syscall_readlinkat(struct vm* vm, int dirfd, uint64_t pathname, uint64_t buf, int bufsiz);
