#include "mini-gdbstub/include/gdbstub.h"
#include "load_linux.h"
#include "utils.h"
#include "vm.h"
#include "gdbstub.h"
#include "guest_inspector.h"
#include <errno.h>
#include <stdint.h>
#include <linux/kvm.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>


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
    
    /* FPU registers */
    GDB_CPU_X86_64_REG_ST0     = 24,
    GDB_CPU_X86_64_REG_ST1     = 25,
    GDB_CPU_X86_64_REG_ST2     = 26,
    GDB_CPU_X86_64_REG_ST3     = 27,
    GDB_CPU_X86_64_REG_ST4     = 28,
    GDB_CPU_X86_64_REG_ST5     = 29,
    GDB_CPU_X86_64_REG_ST6     = 30,
    GDB_CPU_X86_64_REG_ST7     = 31,
    
    GDB_CPU_X86_64_REG_FCTRL   = 32,
    GDB_CPU_X86_64_REG_FSTAT   = 33,
    GDB_CPU_X86_64_REG_FTAG    = 34,
    GDB_CPU_X86_64_REG_FISEG   = 35,
    GDB_CPU_X86_64_REG_FIOFF   = 36,
    GDB_CPU_X86_64_REG_FOSEG   = 37,
    GDB_CPU_X86_64_REG_FOOFF   = 38,
    GDB_CPU_X86_64_REG_FOP     = 39,
    
    /* SSE registers */
    GDB_CPU_X86_64_REG_XMM0    = 40,
    GDB_CPU_X86_64_REG_XMM1    = 41,
    GDB_CPU_X86_64_REG_XMM2    = 42,
    GDB_CPU_X86_64_REG_XMM3    = 43,
    GDB_CPU_X86_64_REG_XMM4    = 44,
    GDB_CPU_X86_64_REG_XMM5    = 45,
    GDB_CPU_X86_64_REG_XMM6    = 46,
    GDB_CPU_X86_64_REG_XMM7    = 47,
    GDB_CPU_X86_64_REG_XMM8    = 48,
    GDB_CPU_X86_64_REG_XMM9    = 49,
    GDB_CPU_X86_64_REG_XMM10   = 50,
    GDB_CPU_X86_64_REG_XMM11   = 51,
    GDB_CPU_X86_64_REG_XMM12   = 52,
    GDB_CPU_X86_64_REG_XMM13   = 53,
    GDB_CPU_X86_64_REG_XMM14   = 54,
    GDB_CPU_X86_64_REG_XMM15   = 55,
    
    /* SSE control/status registers */
    GDB_CPU_X86_64_REG_MXCSR   = 56,
    
    /* Extended registers that may not be used by all GDB versions */
    /* This is the minimum required by modern GDB */
    
    GDB_CPU_X86_64_NUM_REGISTERS = 57
};


static int read_reg(void *args, int regno, size_t *reg_value) {
    struct debug_args* debug_args = (struct debug_args*)args;

    printf("read_reg regno: %d\n", regno);
    
    struct kvm_regs regs;
    if (ioctl(debug_args->vm->vcpufd, KVM_GET_REGS, &regs) < 0) {
        panic("KVM_GET_REGS");
    }
    struct kvm_sregs2 sregs;
    if (ioctl(debug_args->vm->vcpufd, KVM_GET_SREGS2, &sregs) < 0) {
        panic("KVM_GET_SREGS2");
    }

    // FPU registers need to be fetched separately
    struct kvm_fpu fpu;
    if (regno >= GDB_CPU_X86_64_REG_ST0 && regno <= GDB_CPU_X86_64_REG_MXCSR) {
        if (ioctl(debug_args->vm->vcpufd, KVM_GET_FPU, &fpu) < 0) {
            panic("KVM_GET_FPU");
        }
    }

    switch (regno) {
        /* General purpose registers */
        case GDB_CPU_X86_64_REG_RAX:
            *reg_value = regs.rax;
            return 0;
        case GDB_CPU_X86_64_REG_RBX:
            *reg_value = regs.rbx;
            return 0;
        case GDB_CPU_X86_64_REG_RCX:
            *reg_value = regs.rcx;
            return 0;
        case GDB_CPU_X86_64_REG_RDX:
            *reg_value = regs.rdx;
            return 0;
        case GDB_CPU_X86_64_REG_RSI:
            *reg_value = regs.rsi;
            return 0;
        case GDB_CPU_X86_64_REG_RDI:
            *reg_value = regs.rdi;
            return 0;
        case GDB_CPU_X86_64_REG_RBP:
            *reg_value = regs.rbp;
            return 0;
        case GDB_CPU_X86_64_REG_RSP:
            *reg_value = regs.rsp;
            return 0;
            
        /* Additional 64-bit registers */
        case GDB_CPU_X86_64_REG_R8:
            *reg_value = regs.r8;
            return 0;
        case GDB_CPU_X86_64_REG_R9:
            *reg_value = regs.r9;
            return 0;
        case GDB_CPU_X86_64_REG_R10:
            *reg_value = regs.r10;
            return 0;
        case GDB_CPU_X86_64_REG_R11:
            *reg_value = regs.r11;
            return 0;
        case GDB_CPU_X86_64_REG_R12:
            *reg_value = regs.r12;
            return 0;
        case GDB_CPU_X86_64_REG_R13:
            *reg_value = regs.r13;
            return 0;
        case GDB_CPU_X86_64_REG_R14:
            *reg_value = regs.r14;
            return 0;
        case GDB_CPU_X86_64_REG_R15:
            *reg_value = regs.r15;
            return 0;
            
        /* Instruction pointer */
        case GDB_CPU_X86_64_REG_RIP:
            *reg_value = regs.rip;
            return 0;
            
        /* Flags register */
        case GDB_CPU_X86_64_REG_EFLAGS:
            *reg_value = regs.rflags;
            return 0;
            
        /* Segment registers */
        case GDB_CPU_X86_64_REG_CS:
            *reg_value = sregs.cs.selector;
            return 0;
        case GDB_CPU_X86_64_REG_SS:
            *reg_value = sregs.ss.selector;
            return 0;
        case GDB_CPU_X86_64_REG_DS:
            *reg_value = sregs.ds.selector;
            return 0;
        case GDB_CPU_X86_64_REG_ES:
            *reg_value = sregs.es.selector;
            return 0;
        case GDB_CPU_X86_64_REG_FS:
            *reg_value = sregs.fs.selector;
            return 0;
        case GDB_CPU_X86_64_REG_GS:
            *reg_value = sregs.gs.selector;
            return 0;

        /* FPU ST registers - needs special handling for 80-bit format */
        case GDB_CPU_X86_64_REG_ST0:
        case GDB_CPU_X86_64_REG_ST1:
        case GDB_CPU_X86_64_REG_ST2:
        case GDB_CPU_X86_64_REG_ST3:
        case GDB_CPU_X86_64_REG_ST4:
        case GDB_CPU_X86_64_REG_ST5:
        case GDB_CPU_X86_64_REG_ST6:
        case GDB_CPU_X86_64_REG_ST7: {
            // don't read for now
            *reg_value = 0;
            return 0;
        }
            
        /* FPU control registers */
        case GDB_CPU_X86_64_REG_FCTRL:
            *reg_value = fpu.fcw;
            return 0;
        case GDB_CPU_X86_64_REG_FSTAT:
            *reg_value = fpu.fsw;
            return 0;
        case GDB_CPU_X86_64_REG_FTAG:
            *reg_value = fpu.ftwx;
            return 0;
        case GDB_CPU_X86_64_REG_FISEG:
            /* These registers might not be directly accessible through KVM API */
            /* Using 0 as a placeholder */
            *reg_value = 0;
            return 0;
        case GDB_CPU_X86_64_REG_FIOFF:
            *reg_value = 0;
            return 0;
        case GDB_CPU_X86_64_REG_FOSEG:
            *reg_value = 0;
            return 0;
        case GDB_CPU_X86_64_REG_FOOFF:
            *reg_value = 0;
            return 0;
        case GDB_CPU_X86_64_REG_FOP:
            *reg_value = fpu.last_opcode;
            return 0;
            
        /* XMM registers */
        case GDB_CPU_X86_64_REG_XMM0:
        case GDB_CPU_X86_64_REG_XMM1:
        case GDB_CPU_X86_64_REG_XMM2:
        case GDB_CPU_X86_64_REG_XMM3:
        case GDB_CPU_X86_64_REG_XMM4:
        case GDB_CPU_X86_64_REG_XMM5:
        case GDB_CPU_X86_64_REG_XMM6:
        case GDB_CPU_X86_64_REG_XMM7:
        case GDB_CPU_X86_64_REG_XMM8:
        case GDB_CPU_X86_64_REG_XMM9:
        case GDB_CPU_X86_64_REG_XMM10:
        case GDB_CPU_X86_64_REG_XMM11:
        case GDB_CPU_X86_64_REG_XMM12:
        case GDB_CPU_X86_64_REG_XMM13:
        case GDB_CPU_X86_64_REG_XMM14:
        case GDB_CPU_X86_64_REG_XMM15: {
            // don't read for now
            *reg_value = 0;
            return 0;
        }
            
        /* SSE control/status register */
        case GDB_CPU_X86_64_REG_MXCSR:
            *reg_value = fpu.mxcsr;
            return 0;
            
        /*
        default:
            return EFAULT;
        */
        default:
            *reg_value = 0; // not supported -> write 0
            return 0;
            return EFAULT;
    }
    return 0;
}

static int write_reg(void *args, int regno, size_t data) {
    struct debug_args* debug_args = (struct debug_args*)args;

    printf("write_reg regno: %d\n", regno);
    
    struct kvm_regs regs;
    if (ioctl(debug_args->vm->vcpufd, KVM_GET_REGS, &regs) < 0) {
        panic("KVM_GET_REGS");
        return EFAULT;
    }

    struct kvm_sregs2 sregs;
    if (ioctl(debug_args->vm->vcpufd, KVM_GET_SREGS2, &sregs) < 0) {
        panic("KVM_GET_SREGS2");
        return EFAULT;
    }
    
    // For FPU registers
    struct kvm_fpu fpu;
    int fpu_modified = 0;
    
    // Check if we need to fetch the FPU state
    if (regno >= GDB_CPU_X86_64_REG_ST0 && regno <= GDB_CPU_X86_64_REG_MXCSR) {
        if (ioctl(debug_args->vm->vcpufd, KVM_GET_FPU, &fpu) < 0) {
            panic("KVM_GET_FPU");
            return EFAULT;
        }
        fpu_modified = 1;
    }
    
    int sregs_modified = 0;
    
    switch (regno) {
        /* General purpose registers */
        case GDB_CPU_X86_64_REG_RAX:
            regs.rax = data;
            break;
        case GDB_CPU_X86_64_REG_RBX:
            regs.rbx = data;
            break;
        case GDB_CPU_X86_64_REG_RCX:
            regs.rcx = data;
            break;
        case GDB_CPU_X86_64_REG_RDX:
            regs.rdx = data;
            break;
        case GDB_CPU_X86_64_REG_RSI:
            regs.rsi = data;
            break;
        case GDB_CPU_X86_64_REG_RDI:
            regs.rdi = data;
            break;
        case GDB_CPU_X86_64_REG_RBP:
            regs.rbp = data;
            break;
        case GDB_CPU_X86_64_REG_RSP:
            regs.rsp = data;
            break;
            
        /* Additional 64-bit registers */
        case GDB_CPU_X86_64_REG_R8:
            regs.r8 = data;
            break;
        case GDB_CPU_X86_64_REG_R9:
            regs.r9 = data;
            break;
        case GDB_CPU_X86_64_REG_R10:
            regs.r10 = data;
            break;
        case GDB_CPU_X86_64_REG_R11:
            regs.r11 = data;
            break;
        case GDB_CPU_X86_64_REG_R12:
            regs.r12 = data;
            break;
        case GDB_CPU_X86_64_REG_R13:
            regs.r13 = data;
            break;
        case GDB_CPU_X86_64_REG_R14:
            regs.r14 = data;
            break;
        case GDB_CPU_X86_64_REG_R15:
            regs.r15 = data;
            break;
            
        /* Instruction pointer */
        case GDB_CPU_X86_64_REG_RIP:
            regs.rip = data;
            break;
            
        /* Flags register */
        case GDB_CPU_X86_64_REG_EFLAGS:
            regs.rflags = data;
            break;
            
        /* Segment registers */
        case GDB_CPU_X86_64_REG_CS:
            sregs.cs.selector = (uint16_t)data;
            sregs_modified = 1;
            break;
        case GDB_CPU_X86_64_REG_SS:
            sregs.ss.selector = (uint16_t)data;
            sregs_modified = 1;
            break;
        case GDB_CPU_X86_64_REG_DS:
            sregs.ds.selector = (uint16_t)data;
            sregs_modified = 1;
            break;
        case GDB_CPU_X86_64_REG_ES:
            sregs.es.selector = (uint16_t)data;
            sregs_modified = 1;
            break;
        case GDB_CPU_X86_64_REG_FS:
            sregs.fs.selector = (uint16_t)data;
            sregs_modified = 1;
            break;
        case GDB_CPU_X86_64_REG_GS:
            sregs.gs.selector = (uint16_t)data;
            sregs_modified = 1;
            break;
            
        /* FPU ST registers - needs special handling */
        case GDB_CPU_X86_64_REG_ST0:
        case GDB_CPU_X86_64_REG_ST1:
        case GDB_CPU_X86_64_REG_ST2:
        case GDB_CPU_X86_64_REG_ST3:
        case GDB_CPU_X86_64_REG_ST4:
        case GDB_CPU_X86_64_REG_ST5:
        case GDB_CPU_X86_64_REG_ST6:
        case GDB_CPU_X86_64_REG_ST7: {
            // don't set for now
            fpu_modified = 1;
            break;
        }
            
        /* FPU control registers */
        case GDB_CPU_X86_64_REG_FCTRL:
            fpu.fcw = (uint16_t)data;
            fpu_modified = 1;
            break;
        case GDB_CPU_X86_64_REG_FSTAT:
            fpu.fsw = (uint16_t)data;
            fpu_modified = 1;
            break;
        case GDB_CPU_X86_64_REG_FTAG:
            fpu.ftwx = (uint8_t)data;
            fpu_modified = 1;
            break;
        case GDB_CPU_X86_64_REG_FISEG:
            /* These might not be directly accessible via KVM API */
            /* Just mark as handled without making changes */
            break;
        case GDB_CPU_X86_64_REG_FIOFF:
            /* Not directly accessible */
            break;
        case GDB_CPU_X86_64_REG_FOSEG:
            /* Not directly accessible */
            break;
        case GDB_CPU_X86_64_REG_FOOFF:
            /* Not directly accessible */
            break;
        case GDB_CPU_X86_64_REG_FOP:
            fpu.last_opcode = (uint16_t)data;
            fpu_modified = 1;
            break;
            
        /* XMM registers */
        case GDB_CPU_X86_64_REG_XMM0:
        case GDB_CPU_X86_64_REG_XMM1:
        case GDB_CPU_X86_64_REG_XMM2:
        case GDB_CPU_X86_64_REG_XMM3:
        case GDB_CPU_X86_64_REG_XMM4:
        case GDB_CPU_X86_64_REG_XMM5:
        case GDB_CPU_X86_64_REG_XMM6:
        case GDB_CPU_X86_64_REG_XMM7:
        case GDB_CPU_X86_64_REG_XMM8:
        case GDB_CPU_X86_64_REG_XMM9:
        case GDB_CPU_X86_64_REG_XMM10:
        case GDB_CPU_X86_64_REG_XMM11:
        case GDB_CPU_X86_64_REG_XMM12:
        case GDB_CPU_X86_64_REG_XMM13:
        case GDB_CPU_X86_64_REG_XMM14:
        case GDB_CPU_X86_64_REG_XMM15: {
            // don't set for now
            fpu_modified = 1;
            break;
        }
            
        /* SSE control register */
        case GDB_CPU_X86_64_REG_MXCSR:
            fpu.mxcsr = (uint32_t)data;
            fpu_modified = 1;
            break;
            
        default:
            return EFAULT;
    }

    // Apply the changes to the KVM virtual CPU
    if (ioctl(debug_args->vm->vcpufd, KVM_SET_REGS, &regs) < 0) {
        panic("KVM_SET_REGS");
        return EFAULT;
    }

    // Only update segment registers if they were modified
    if (sregs_modified) {
        if (ioctl(debug_args->vm->vcpufd, KVM_SET_SREGS2, &sregs) < 0) {
            panic("KVM_SET_SREGS2");
            return EFAULT;
        }
    }
    
    // Only update FPU state if any FPU registers were modified
    if (fpu_modified) {
        if (ioctl(debug_args->vm->vcpufd, KVM_SET_FPU, &fpu) < 0) {
            panic("KVM_SET_FPU");
            return EFAULT;
        }
    }
    
    return 0;
}

static int read_mem(void *args, size_t addr, size_t len, void *val) {
    printf("read_mem addr: %p, len: %ld\n", (void*)addr, len);

    struct debug_args* debug_args = (struct debug_args*)args;
    read_buffer_host(debug_args->vm, addr, val, len);
    return 0;
}

static int write_mem(void *args, size_t addr, size_t len, void *val) {
    printf("write_mem addr: %p, len: %ld\n", (void*)addr, len);

    struct debug_args* debug_args = (struct debug_args*)args;
    write_buffer_guest(debug_args->vm, addr, val, len);
    return 0;
}

static gdb_action_t cont(void *args) {
    printf("continue\n");

    struct debug_args* debug_args = (struct debug_args*)args;

    int exit_code;
    while ((exit_code = vm_run(debug_args->vm)) != KVM_EXIT_DEBUG) {
        vm_exit_handler(exit_code, debug_args->vm, debug_args->linux_proc);
    }

    return ACT_RESUME;
}

static gdb_action_t stepi(void *args) {
    printf("stepi\n");
    struct debug_args* debug_args = (struct debug_args*)args;

    vm_set_debug_step(debug_args->vm, true);
    int exit_code;
    while ((exit_code = vm_run(debug_args->vm)) != KVM_EXIT_DEBUG) {
        vm_exit_handler(exit_code, debug_args->vm, debug_args->linux_proc);
    }
    vm_set_debug_step(debug_args->vm, false);

    return ACT_RESUME;
}

static bool set_bp(void *args, size_t addr, bp_type_t type) {
    printf("set_bp addr: %p, type: %d\n", (void*)addr, type);
    struct debug_args* debug_args = (struct debug_args*)args;

    if (type != BP_SOFTWARE) {
        return false;
    }
    /*
    do nohing??
    */

    return true;
}

static bool del_bp(void *args, size_t addr, bp_type_t type) {
    printf("del_bp addr: %p, type: %d\n", (void*)addr, type);
    struct debug_args* debug_args = (struct debug_args*)args;

    /*
    do nohing??
    */

    return true;
}

static void on_interrupt(void *args) {
    printf("on_interrupt\n");
    struct debug_args* debug_args = (struct debug_args*)args;
    /*
    exit ??
    */
    exit(EXIT_SUCCESS);
}

arch_info_t arch_info = {
    .smp = 1,
    .reg_num = 73, // bho
    .reg_byte = 8,
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


void debug_start(struct debug_args* debug_args) {

    gdbstub_t gdbstub;

    if (!gdbstub_init(&gdbstub, &ops, arch_info, "127.0.0.1:1234")) {
        panic("Fail to create socket");
    }

    if (!gdbstub_run(&gdbstub, (void *)debug_args)) {
        panic("Fail to run in debug mode");
    }

    gdbstub_close(&gdbstub);
}