#include <assert.h>
#include <errno.h>
#include <linux/kvm.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include "guest_inspector.h"
#include "mygdbstub.h"
#include "utils.h"
#include "vm.h"

uint8_t break_instr = 0xcc;

#define TARGET_X86_64 "<target version=\"1.0\"><architecture>i386:x86-64</architecture></target>"

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

	/* SSE control/status registers */
	GDB_CPU_X86_64_REG_MXCSR = 56,

	/* AVX YMM registers */
	GDB_CPU_X86_64_REG_YMM0 = 57,
	GDB_CPU_X86_64_REG_YMM1 = 58,
	GDB_CPU_X86_64_REG_YMM2 = 59,
	GDB_CPU_X86_64_REG_YMM3 = 60,
	GDB_CPU_X86_64_REG_YMM4 = 61,
	GDB_CPU_X86_64_REG_YMM5 = 62,
	GDB_CPU_X86_64_REG_YMM6 = 63,
	GDB_CPU_X86_64_REG_YMM7 = 64,
	GDB_CPU_X86_64_REG_YMM8 = 65,
	GDB_CPU_X86_64_REG_YMM9 = 66,
	GDB_CPU_X86_64_REG_YMM10 = 67,
	GDB_CPU_X86_64_REG_YMM11 = 68,
	GDB_CPU_X86_64_REG_YMM12 = 69,
	GDB_CPU_X86_64_REG_YMM13 = 70,
	GDB_CPU_X86_64_REG_YMM14 = 71,
	GDB_CPU_X86_64_REG_YMM15 = 72,

	GDB_CPU_X86_64_REG_COUNT = 73
};

void debug_init(struct debug_args *debug_args)
{
	// init breakpoints
	memset(debug_args->breakpoints, 0, sizeof(debug_args->breakpoints));
	// read all registers
	if (ioctl(debug_args->vm->vcpufd, KVM_GET_REGS, &debug_args->regs) < 0) {
		PANIC_PERROR("KVM_GET_REGS");
	}
	if (ioctl(debug_args->vm->vcpufd, KVM_GET_SREGS2, &debug_args->sregs) < 0) {
		PANIC_PERROR("KVM_GET_SREGS2");
	}
	if (ioctl(debug_args->vm->vcpufd, KVM_GET_FPU, &debug_args->fpu) < 0) {
		PANIC_PERROR("KVM_GET_FPU");
	}
}

void debug_cycle(struct debug_args *debug_args)
{
	// write all registers
	if (ioctl(debug_args->vm->vcpufd, KVM_SET_REGS, &debug_args->regs) < 0) {
		PANIC_PERROR("KVM_SET_REGS");
	}
	if (ioctl(debug_args->vm->vcpufd, KVM_SET_SREGS2, &debug_args->sregs) < 0) {
		PANIC_PERROR("KVM_SET_SREGS2");
	}
	if (ioctl(debug_args->vm->vcpufd, KVM_SET_FPU, &debug_args->fpu) < 0) {
		PANIC_PERROR("KVM_SET_FPU");
	}

	int exit_code;
	while ((exit_code = vm_run(debug_args->vm)) != KVM_EXIT_DEBUG) {
		vm_exit_handler(exit_code, debug_args->vm, debug_args->linux_proc);
	}

	// read all registers
	if (ioctl(debug_args->vm->vcpufd, KVM_GET_REGS, &debug_args->regs) < 0) {
		PANIC_PERROR("KVM_GET_REGS");
	}
	if (ioctl(debug_args->vm->vcpufd, KVM_GET_SREGS2, &debug_args->sregs) < 0) {
		PANIC_PERROR("KVM_GET_SREGS2");
	}
	if (ioctl(debug_args->vm->vcpufd, KVM_GET_FPU, &debug_args->fpu) < 0) {
		PANIC_PERROR("KVM_GET_FPU");
	}
}

void *regptr(int regno, struct debug_args *debug_args)
{
	void *reg_ptr = NULL;
	switch (regno) {
	/* General purpose registers */
	case GDB_CPU_X86_64_REG_RAX:
		reg_ptr = &debug_args->regs.rax;
		break;
	case GDB_CPU_X86_64_REG_RBX:
		reg_ptr = &debug_args->regs.rbx;
		break;
	case GDB_CPU_X86_64_REG_RCX:
		reg_ptr = &debug_args->regs.rcx;
		break;
	case GDB_CPU_X86_64_REG_RDX:
		reg_ptr = &debug_args->regs.rdx;
		break;
	case GDB_CPU_X86_64_REG_RSI:
		reg_ptr = &debug_args->regs.rsi;
		break;
	case GDB_CPU_X86_64_REG_RDI:
		reg_ptr = &debug_args->regs.rdi;
		break;
	case GDB_CPU_X86_64_REG_RBP:
		reg_ptr = &debug_args->regs.rbp;
		break;
	case GDB_CPU_X86_64_REG_RSP:
		reg_ptr = &debug_args->regs.rsp;
		break;

	/* Additional 64-bit registers */
	case GDB_CPU_X86_64_REG_R8:
		reg_ptr = &debug_args->regs.r8;
		break;
	case GDB_CPU_X86_64_REG_R9:
		reg_ptr = &debug_args->regs.r9;
		break;
	case GDB_CPU_X86_64_REG_R10:
		reg_ptr = &debug_args->regs.r10;
		break;
	case GDB_CPU_X86_64_REG_R11:
		reg_ptr = &debug_args->regs.r11;
		break;
	case GDB_CPU_X86_64_REG_R12:
		reg_ptr = &debug_args->regs.r12;
		break;
	case GDB_CPU_X86_64_REG_R13:
		reg_ptr = &debug_args->regs.r13;
		break;
	case GDB_CPU_X86_64_REG_R14:
		reg_ptr = &debug_args->regs.r14;
		break;
	case GDB_CPU_X86_64_REG_R15:
		reg_ptr = &debug_args->regs.r15;
		break;

	/* Instruction pointer */
	case GDB_CPU_X86_64_REG_RIP:
		reg_ptr = &debug_args->regs.rip;
		break;

	/* Flags register */
	case GDB_CPU_X86_64_REG_EFLAGS:
		reg_ptr = &debug_args->regs.rflags;
		break;

	/* Segment registers */
	case GDB_CPU_X86_64_REG_CS:
		reg_ptr = &debug_args->sregs.cs;
		break;
	case GDB_CPU_X86_64_REG_SS:
		reg_ptr = &debug_args->sregs.ss;
		break;
	case GDB_CPU_X86_64_REG_DS:
		reg_ptr = &debug_args->sregs.ds;
		break;
	case GDB_CPU_X86_64_REG_ES:
		reg_ptr = &debug_args->sregs.es;
		break;
	case GDB_CPU_X86_64_REG_FS:
		reg_ptr = &debug_args->sregs.fs;
		break;
	case GDB_CPU_X86_64_REG_GS:
		reg_ptr = &debug_args->sregs.gs;
		break;

	/* FPU ST registers (80-bit floating point) */
	case GDB_CPU_X86_64_REG_ST0:
		reg_ptr = debug_args->fpu.fpr[0];
		break;
	case GDB_CPU_X86_64_REG_ST1:
		reg_ptr = debug_args->fpu.fpr[1];
		break;
	case GDB_CPU_X86_64_REG_ST2:
		reg_ptr = debug_args->fpu.fpr[2];
		break;
	case GDB_CPU_X86_64_REG_ST3:
		reg_ptr = debug_args->fpu.fpr[3];
		break;
	case GDB_CPU_X86_64_REG_ST4:
		reg_ptr = debug_args->fpu.fpr[4];
		break;
	case GDB_CPU_X86_64_REG_ST5:
		reg_ptr = debug_args->fpu.fpr[5];
		break;
	case GDB_CPU_X86_64_REG_ST6:
		reg_ptr = debug_args->fpu.fpr[6];
		break;
	case GDB_CPU_X86_64_REG_ST7:
		reg_ptr = debug_args->fpu.fpr[7];
		break;

	/* FPU control registers */
	case GDB_CPU_X86_64_REG_FCTRL:
		reg_ptr = &debug_args->fpu.fcw;
		break;
	case GDB_CPU_X86_64_REG_FSTAT:
		reg_ptr = &debug_args->fpu.fsw;
		break;
	case GDB_CPU_X86_64_REG_FTAG:
		reg_ptr = &debug_args->fpu.ftwx;
		break;
	case GDB_CPU_X86_64_REG_FISEG:
		reg_ptr = NULL;
		break;
	case GDB_CPU_X86_64_REG_FIOFF:
		reg_ptr = &debug_args->fpu.last_ip;
		break;
	case GDB_CPU_X86_64_REG_FOSEG:
		reg_ptr = NULL;
		break;
	case GDB_CPU_X86_64_REG_FOOFF:
		reg_ptr = &debug_args->fpu.last_dp;
		break;
	case GDB_CPU_X86_64_REG_FOP:
		reg_ptr = &debug_args->fpu.last_opcode;
		break;

	/* SSE registers (XMM) */
	case GDB_CPU_X86_64_REG_XMM0:
		reg_ptr = debug_args->fpu.xmm[0];
		break;
	case GDB_CPU_X86_64_REG_XMM1:
		reg_ptr = &debug_args->fpu.xmm[1];
		break;
	case GDB_CPU_X86_64_REG_XMM2:
		reg_ptr = &debug_args->fpu.xmm[2];
		break;
	case GDB_CPU_X86_64_REG_XMM3:
		reg_ptr = &debug_args->fpu.xmm[3];
		break;
	case GDB_CPU_X86_64_REG_XMM4:
		reg_ptr = &debug_args->fpu.xmm[4];
		break;
	case GDB_CPU_X86_64_REG_XMM5:
		reg_ptr = &debug_args->fpu.xmm[5];
		break;
	case GDB_CPU_X86_64_REG_XMM6:
		reg_ptr = &debug_args->fpu.xmm[6];
		break;
	case GDB_CPU_X86_64_REG_XMM7:
		reg_ptr = &debug_args->fpu.xmm[7];
		break;
	case GDB_CPU_X86_64_REG_XMM8:
		reg_ptr = &debug_args->fpu.xmm[8];
		break;
	case GDB_CPU_X86_64_REG_XMM9:
		reg_ptr = &debug_args->fpu.xmm[9];
		break;
	case GDB_CPU_X86_64_REG_XMM10:
		reg_ptr = &debug_args->fpu.xmm[10];
		break;
	case GDB_CPU_X86_64_REG_XMM11:
		reg_ptr = &debug_args->fpu.xmm[11];
		break;
	case GDB_CPU_X86_64_REG_XMM12:
		reg_ptr = &debug_args->fpu.xmm[12];
		break;
	case GDB_CPU_X86_64_REG_XMM13:
		reg_ptr = &debug_args->fpu.xmm[13];
		break;
	case GDB_CPU_X86_64_REG_XMM14:
		reg_ptr = &debug_args->fpu.xmm[14];
		break;
	case GDB_CPU_X86_64_REG_XMM15:
		reg_ptr = &debug_args->fpu.xmm[15];
		break;

	/* SSE control register */
	case GDB_CPU_X86_64_REG_MXCSR:
		reg_ptr = &debug_args->fpu.mxcsr;
		break;

	case GDB_CPU_X86_64_REG_YMM0:
	case GDB_CPU_X86_64_REG_YMM1:
	case GDB_CPU_X86_64_REG_YMM2:
	case GDB_CPU_X86_64_REG_YMM3:
	case GDB_CPU_X86_64_REG_YMM4:
	case GDB_CPU_X86_64_REG_YMM5:
	case GDB_CPU_X86_64_REG_YMM6:
	case GDB_CPU_X86_64_REG_YMM7:
	case GDB_CPU_X86_64_REG_YMM8:
	case GDB_CPU_X86_64_REG_YMM9:
	case GDB_CPU_X86_64_REG_YMM10:
	case GDB_CPU_X86_64_REG_YMM11:
	case GDB_CPU_X86_64_REG_YMM12:
	case GDB_CPU_X86_64_REG_YMM13:
	case GDB_CPU_X86_64_REG_YMM14:
	case GDB_CPU_X86_64_REG_YMM15:
		reg_ptr = NULL;
		break;
	}
	return reg_ptr;
}

static int read_reg(void *args, int regno, void *reg_value)
{
	struct debug_args *debug_args = (struct debug_args *)args;

#ifdef DEBUG
	printf("read_reg regno: %d\n", regno);
#endif

	if (regno >= GDB_CPU_X86_64_REG_COUNT)
		return EFAULT;

	void *reg_ptr = regptr(regno, debug_args);
	if (reg_ptr == NULL) {
		memset(reg_value, 0, x86_64_regs_size[regno]);
	} else {
		memcpy(reg_value, reg_ptr, x86_64_regs_size[regno]);
	}

	return 0;
}

static int write_reg(void *args, int regno, void *data)
{
	struct debug_args *debug_args = (struct debug_args *)args;

#ifdef DEBUG
	printf("write_reg regno: %d\n", regno);
#endif

	if (regno >= GDB_CPU_X86_64_REG_COUNT)
		return EFAULT;

	void *reg_ptr = regptr(regno, debug_args);
	if (reg_ptr == NULL) {
		memset(data, 0, x86_64_regs_size[regno]);
	} else {
		memcpy(reg_ptr, data, x86_64_regs_size[regno]);
	}

	return 0;
}

int memory_with_breakpoints(struct breakpoint breakpoints[], uint8_t *buff, size_t addr, size_t len)
{
	for (int i = 0; i < BREAKPOINTS_MAX_NUM; i++) {
		struct breakpoint *bp = &breakpoints[i];
		// this breakpoint is in that memory -> set it
		if (bp->addr >= addr && bp->addr < addr + len) {
			buff[bp->addr - addr] = break_instr;
		}
	}
	return 0;
}

int memory_without_breakpoints(struct breakpoint breakpoints[], uint8_t *buff, size_t addr,
			       size_t len)
{
	for (int i = 0; i < BREAKPOINTS_MAX_NUM; i++) {
		struct breakpoint *bp = &breakpoints[i];
		// this breakpoint is in that memory -> set it
		if (bp->addr >= addr && bp->addr < addr + len) {
			buff[bp->addr - addr] = bp->original_data;
		}
	}
	return 0;
}

static int read_mem(void *args, size_t addr, size_t len, void *val)
{
#ifdef DEBUG
	printf("read_mem addr: %p, len: %ld\n", (void *)addr, len);
#endif

	struct debug_args *debug_args = (struct debug_args *)args;

	if (read_buffer_host(debug_args->vm, addr, val, len) < 0) {
		return EFAULT;
	}

	memory_without_breakpoints(debug_args->breakpoints, val, addr, len);

	return 0;
}

static int write_mem(void *args, size_t addr, size_t len, void *val)
{
#ifdef DEBUG
	printf("write_mem addr: %p, len: %ld\n", (void *)addr, len);
#endif
	struct debug_args *debug_args = (struct debug_args *)args;

	memory_with_breakpoints(debug_args->breakpoints, val, addr, len);

	if (write_buffer_guest(debug_args->vm, addr, val, len) < 0) {
		return EFAULT;
	}
	return 0;
}

static gdb_action_t cont(void *args)
{
#ifdef DEBUG
	printf("continue\n");
#endif

	struct debug_args *debug_args = (struct debug_args *)args;

	debug_cycle(debug_args);

	return ACT_RESUME;
}

static gdb_action_t stepi(void *args)
{
#ifdef DEBUG
	printf("stepi\n");
#endif
	struct debug_args *debug_args = (struct debug_args *)args;

	vm_set_debug_step(debug_args->vm, true);
	debug_cycle(debug_args);
	vm_set_debug_step(debug_args->vm, false);

	return ACT_RESUME;
}

static bool set_bp(void *args, size_t addr, bp_type_t type)
{
#ifdef DEBUG
	printf("set_bp addr: %p, type: %d\n", (void *)addr, type);
#endif
	struct debug_args *debug_args = (struct debug_args *)args;

	if (type != BP_SOFTWARE) {
		return false;
	}

	for (int i = 0; i < BREAKPOINTS_MAX_NUM; i++) {
		struct breakpoint *bp = &debug_args->breakpoints[i];
		// empyt breakpoint found
		if (bp->addr == 0) {
			bp->addr = addr;

			// read the origina data
			int ret = read_buffer_host(debug_args->vm, addr, &bp->original_data,
						   sizeof(bp->original_data));
			if (ret < 0)
				return false; // cannot access memory

			// replace it with break_inst
			ret = write_buffer_guest(debug_args->vm, addr, &break_instr,
						 sizeof(break_instr));
			if (ret < 0)
				return false; // cannot access memory

			return true;
		}
	}
	// max number of breakpoints reached
	return false;
}

static bool del_bp(void *args, size_t addr, bp_type_t type __attribute__((unused)))
{
#ifdef DEBUG
	printf("del_bp addr: %p, type: %d\n", (void *)addr, type);
#endif
	struct debug_args *debug_args = (struct debug_args *)args;

	for (int i = 0; i < BREAKPOINTS_MAX_NUM; i++) {
		struct breakpoint *bp = &debug_args->breakpoints[i];
		// breakpoint found
		if (bp->addr == addr) {
			bp->addr = 0;

			// restore the instruction
			int ret = write_buffer_guest(debug_args->vm, addr, &bp->original_data,
						     sizeof(bp->original_data));
			if (ret < 0)
				return false; // cannot access memory

			return true;
		}
	}

	// breakpoint does't exisits
	return false;
}

static void on_interrupt(void *args __attribute__((unused)))
{
#ifdef DEBUG
	printf("on_interrupt\n");
#endif
	// struct debug_args* debug_args = (struct debug_args*)args;

	/*
	exit ??
	*/
	exit(EXIT_SUCCESS);
}

arch_info_t arch_info = {
	.smp = 1,
	.reg_num = GDB_CPU_X86_64_NUM_REGISTERS, // bho
	.reg_byte = 0,
	.regs_byte = x86_64_regs_size,
	.target_desc = TARGET_X86_64 // bho
};

struct target_ops ops = {
	.read_reg = read_reg,
	.write_reg = write_reg,
	.read_mem = read_mem,
	.write_mem = write_mem,
	.cont = cont,
	.stepi = stepi,
	.set_bp = set_bp,
	.del_bp = del_bp,
	.on_interrupt = on_interrupt,
};

void debug_start(char *debug_server, struct debug_args *debug_args)
{
	debug_init(debug_args);

	gdbstub_t gdbstub;

	if (!gdbstub_init(&gdbstub, &ops, arch_info, debug_server)) {
		PANIC("Fail to create socket");
	}

	if (!gdbstub_run(&gdbstub, (void *)debug_args)) {
		PANIC("Fail to run in debug mode");
	}

	gdbstub_close(&gdbstub);
}
