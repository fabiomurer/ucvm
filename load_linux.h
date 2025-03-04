#pragma once

#include <stdint.h>
#include <sys/types.h>

struct linux_proc {
    pid_t pid;
    uint64_t brk;
    uint64_t rip;
    uint64_t rsp;
};

void load_linux(char** argv, struct linux_proc* linux_proc);