#pragma once

#include "mini-gdbstub/include/gdbstub.h"

struct debug_args {
    struct vm* vm;
    struct linux_proc* linux_proc;
};

void debug_start(struct debug_args* debug_args);