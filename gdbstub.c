#include "mini-gdbstub/include/gdbstub.h"
#include "vm.h"
#include <stdint.h>


#define TARGET_X86_64 \
    "<target version=\"1.0\"><architecture>i386:x86-64</architecture></target>"

enum GDB_REGISTER {
    /* 64-bit general purpose registers */
    GDB_CPU_X86_64_REG_RAX     = 0,
    GDB_CPU_X86_64_REG_RBX     = 1,
    GDB_CPU_X86_64_REG_RCX     = 2,
    GDB_CPU_X86_64_REG_RDX     = 3,
    GDB_CPU_X86_64_REG_RSI     = 4,
    GDB_CPU_X86_64_REG_RDI     = 5,
    GDB_CPU_X86_64_REG_RBP     = 6,
    GDB_CPU_X86_64_REG_RSP     = 7,
    GDB_CPU_X86_64_REG_R8      = 8,
    GDB_CPU_X86_64_REG_R9      = 9,
    GDB_CPU_X86_64_REG_R10     = 10,
    GDB_CPU_X86_64_REG_R11     = 11,
    GDB_CPU_X86_64_REG_R12     = 12,
    GDB_CPU_X86_64_REG_R13     = 13,
    GDB_CPU_X86_64_REG_R14     = 14,
    GDB_CPU_X86_64_REG_R15     = 15,
    GDB_CPU_X86_64_REG_RIP     = 16,
    GDB_CPU_X86_64_REG_EFLAGS  = 17,
    GDB_CPU_X86_64_REG_CS      = 18,
    GDB_CPU_X86_64_REG_SS      = 19,
    GDB_CPU_X86_64_REG_DS      = 20,
    GDB_CPU_X86_64_REG_ES      = 21,
    GDB_CPU_X86_64_REG_FS      = 22,
    GDB_CPU_X86_64_REG_GS      = 23,
    /* FPU/SSE/AVX registers would follow... */
    
    GDB_CPU_X86_64_NUM_REGISTERS = 24  /* Base register count without FPU/SIMD */
};

static int read_reg(void *args, int regno, size_t *reg_value) {
    struct vm* vm = (struct vm*)args;

    return 0;
}

static int write_reg(void *args, int regno, size_t data) {
    struct vm* vm = (struct vm*)args;

    return 0;
}

static int read_mem(void *args, size_t addr, size_t len, void *val) {
    struct vm* vm = (struct vm*)args;

    return 0;
}

static int write_mem(void *args, size_t addr, size_t len, void *val) {
    struct vm* vm = (struct vm*)args;

    return 0;
}

static gdb_action_t cont(void *args) {
    struct vm* vm = (struct vm*)args;

    return ACT_RESUME;
}

static gdb_action_t stepi(void *args) {
    struct vm* vm = (struct vm*)args;

    return ACT_RESUME;
}

static bool set_bp(void *args, size_t addr, bp_type_t type) {
    struct vm* vm = (struct vm*)args;

    return true;
}

static bool del_bp(void *args, size_t addr, bp_type_t type) {
    struct vm* vm = (struct vm*)args;

    return true;
}

static void on_interrupt(void *args) {
    struct vm* vm = (struct vm*)args;
}

arch_info_t arch_info = {
    .smp = 1,
    .reg_num = GDB_CPU_X86_64_NUM_REGISTERS, // bho
    .reg_byte = sizeof(uintptr_t),
    .target_desc = TARGET_X86_64 // bho
};

struct target_ops ops = {
    .read_reg       = read_reg,
    .write_reg      = write_reg,
    .read_mem       = read_mem,
    .write_mem      = write_mem,
    .cont           = cont,
    .stepi          = stepi,
    .set_bp         = set_bp,
    .del_bp         = del_bp,
    .on_interrupt   = on_interrupt,
};
