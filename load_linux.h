#pragma once

#include <stdint.h>
#include <sys/types.h>

struct linux_proc {
    pid_t pid;

    // for brk syscall
    uint64_t brk;
    uint64_t rip;
    uint64_t rsp;

    // for threads (i dunno :( )
    uint64_t clear_child_tid;
    uint64_t robust_list_head_ptr;
};

void load_linux(char** argv, struct linux_proc* linux_proc);