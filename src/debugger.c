#define _GNU_SOURCE

#include <stdio.h>
#include <sys/ioctl.h>

#include "vm.h"
#include "guest_inspector.h"
#include "debugger.h"
#include "utils.h"

uint8_t break_instr = 0xcc;

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
		vm_exit_handler(exit_code, debug_args->vm);
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
		reg_ptr = &debug_args->sregs.cs.selector;
		break;
	case GDB_CPU_X86_64_REG_SS:
		reg_ptr = &debug_args->sregs.ss.selector;
		break;
	case GDB_CPU_X86_64_REG_DS:
		reg_ptr = &debug_args->sregs.ds.selector;
		break;
	case GDB_CPU_X86_64_REG_ES:
		reg_ptr = &debug_args->sregs.es.selector;
		break;
	case GDB_CPU_X86_64_REG_FS:
		reg_ptr = &debug_args->sregs.fs.selector;
		break;
	case GDB_CPU_X86_64_REG_GS:
		reg_ptr = &debug_args->sregs.gs.selector;
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

size_t get_reg_bytes(int regno)
{
	if (regno < GDB_CPU_X86_64_REG_COUNT) {
		return x86_64_regs_size[regno];
	} else {
		return 0;
	}
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
		// Cannot write to unsupported registers - do nothing
		return 0;
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

arch_info_t arch_info = { .target_desc = TARGET_X86_64,
			  .smp = 1,
			  .reg_num = GDB_CPU_X86_64_REG_COUNT };

struct target_ops ops = { .cont = cont,
			  .stepi = stepi,
			  .get_reg_bytes = get_reg_bytes,
			  .read_reg = read_reg,
			  .write_reg = write_reg,
			  .read_mem = read_mem,
			  .write_mem = write_mem,
			  .set_bp = set_bp,
			  .del_bp = del_bp,
			  .on_interrupt = on_interrupt,
			  .set_cpu = nullptr,
			  .get_cpu = nullptr };

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
