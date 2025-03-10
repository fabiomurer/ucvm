#pragma once

#include "mini-gdbstub/include/gdbstub.h"
#include <stdint.h>

#define BREAKPOINTS_MAX_NUM 256

static uint8_t break_instr = 0xcc;

struct breakpoint {
  size_t addr;
  uint8_t original_data;
};

struct debug_args {
    struct vm* vm;
    struct linux_proc* linux_proc;
    struct breakpoint breakpoints[BREAKPOINTS_MAX_NUM];
};

void debug_start(struct debug_args* debug_args);