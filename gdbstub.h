#pragma once

#include "mini-gdbstub/include/gdbstub.h"
#include <asm/kvm.h>
#include <linux/kvm.h>
#include <stdint.h>

#define BREAKPOINTS_MAX_NUM 256

extern uint8_t break_instr;

struct breakpoint {
  size_t addr;
  uint8_t original_data;
};

struct debug_args {
    struct vm* vm;
    struct linux_proc* linux_proc;
    struct breakpoint breakpoints[BREAKPOINTS_MAX_NUM];
    struct kvm_regs regs;
    struct kvm_sregs2 sregs;
    struct kvm_fpu fpu;
};

void debug_start(char* debug_server, struct debug_args* debug_args);
