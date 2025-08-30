#pragma once

#include <linux/kvm.h>
#include <stdint.h>

#include "gdbstub.h"

#define BREAKPOINTS_MAX_NUM 256

struct breakpoint {
	size_t addr;
	uint8_t original_data;
};

struct debug_args {
	struct vm *vm;
	struct breakpoint breakpoints[BREAKPOINTS_MAX_NUM];
	struct kvm_regs regs;
	struct kvm_sregs2 sregs;
	struct kvm_fpu fpu;
};

void debug_start(char *debug_server, struct debug_args *debug_args);
