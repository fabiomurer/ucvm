#pragma once

#include <linux/kvm.h>
#include <stdint.h>

#include "gdbstub.h"

#define BREAKPOINTS_MAX_NUM 256

enum GDB_REGISTER {
	/* 64-bit general purpose registers */
	GDB_CPU_X86_64_REG_RAX = 0,
	GDB_CPU_X86_64_REG_RBX = 1,
	GDB_CPU_X86_64_REG_RCX = 2,
	GDB_CPU_X86_64_REG_RDX = 3,
	GDB_CPU_X86_64_REG_RSI = 4,
	GDB_CPU_X86_64_REG_RDI = 5,
	GDB_CPU_X86_64_REG_RBP = 6,
	GDB_CPU_X86_64_REG_RSP = 7,
	GDB_CPU_X86_64_REG_R8 = 8,
	GDB_CPU_X86_64_REG_R9 = 9,
	GDB_CPU_X86_64_REG_R10 = 10,
	GDB_CPU_X86_64_REG_R11 = 11,
	GDB_CPU_X86_64_REG_R12 = 12,
	GDB_CPU_X86_64_REG_R13 = 13,
	GDB_CPU_X86_64_REG_R14 = 14,
	GDB_CPU_X86_64_REG_R15 = 15,
	GDB_CPU_X86_64_REG_RIP = 16,
	GDB_CPU_X86_64_REG_EFLAGS = 17,
	GDB_CPU_X86_64_REG_CS = 18,
	GDB_CPU_X86_64_REG_SS = 19,
	GDB_CPU_X86_64_REG_DS = 20,
	GDB_CPU_X86_64_REG_ES = 21,
	GDB_CPU_X86_64_REG_FS = 22,
	GDB_CPU_X86_64_REG_GS = 23,

	/* FPU registers */
	GDB_CPU_X86_64_REG_ST0 = 24,
	GDB_CPU_X86_64_REG_ST1 = 25,
	GDB_CPU_X86_64_REG_ST2 = 26,
	GDB_CPU_X86_64_REG_ST3 = 27,
	GDB_CPU_X86_64_REG_ST4 = 28,
	GDB_CPU_X86_64_REG_ST5 = 29,
	GDB_CPU_X86_64_REG_ST6 = 30,
	GDB_CPU_X86_64_REG_ST7 = 31,

	GDB_CPU_X86_64_REG_FCTRL = 32,
	GDB_CPU_X86_64_REG_FSTAT = 33,
	GDB_CPU_X86_64_REG_FTAG = 34,
	GDB_CPU_X86_64_REG_FISEG = 35,
	GDB_CPU_X86_64_REG_FIOFF = 36,
	GDB_CPU_X86_64_REG_FOSEG = 37,
	GDB_CPU_X86_64_REG_FOOFF = 38,
	GDB_CPU_X86_64_REG_FOP = 39,

	/* SSE registers */
	GDB_CPU_X86_64_REG_XMM0 = 40,
	GDB_CPU_X86_64_REG_XMM1 = 41,
	GDB_CPU_X86_64_REG_XMM2 = 42,
	GDB_CPU_X86_64_REG_XMM3 = 43,
	GDB_CPU_X86_64_REG_XMM4 = 44,
	GDB_CPU_X86_64_REG_XMM5 = 45,
	GDB_CPU_X86_64_REG_XMM6 = 46,
	GDB_CPU_X86_64_REG_XMM7 = 47,
	GDB_CPU_X86_64_REG_XMM8 = 48,
	GDB_CPU_X86_64_REG_XMM9 = 49,
	GDB_CPU_X86_64_REG_XMM10 = 50,
	GDB_CPU_X86_64_REG_XMM11 = 51,
	GDB_CPU_X86_64_REG_XMM12 = 52,
	GDB_CPU_X86_64_REG_XMM13 = 53,
	GDB_CPU_X86_64_REG_XMM14 = 54,
	GDB_CPU_X86_64_REG_XMM15 = 55,

	GDB_CPU_X86_64_REG_MXCSR,

	/* AVX YMM registers */
	GDB_CPU_X86_64_REG_YMM0,
	GDB_CPU_X86_64_REG_YMM1,
	GDB_CPU_X86_64_REG_YMM2,
	GDB_CPU_X86_64_REG_YMM3,
	GDB_CPU_X86_64_REG_YMM4,
	GDB_CPU_X86_64_REG_YMM5,
	GDB_CPU_X86_64_REG_YMM6,
	GDB_CPU_X86_64_REG_YMM7,
	GDB_CPU_X86_64_REG_YMM8,
	GDB_CPU_X86_64_REG_YMM9,
	GDB_CPU_X86_64_REG_YMM10,
	GDB_CPU_X86_64_REG_YMM11,
	GDB_CPU_X86_64_REG_YMM12,
	GDB_CPU_X86_64_REG_YMM13,
	GDB_CPU_X86_64_REG_YMM14,
	GDB_CPU_X86_64_REG_YMM15,

	GDB_CPU_X86_64_REG_COUNT
};

/* Register sizes in bytes for x86_64 architecture */
static const size_t x86_64_regs_size[GDB_CPU_X86_64_REG_COUNT] = {
	/*general porpouse registers*/
	8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 4, /*32-bit flags */
	/*segments registers*/
	4, 4, 4, 4, 4, 4,
	/*fpu registers*/
	10, 10, 10, 10, 10, 10, 10, 10,
	/*fpu controls registers*/
	4, 4, 4, 4, 4, 4, 4, 4,
	/*sse registers*/
	16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
	/*sse control/status register*/
	4,

	/* AVX YMM registers*/
	16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
	/* mxcsr*/
};

extern uint8_t break_instr;

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
