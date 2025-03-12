#include "mini-gdbstub/include/gdbstub.h"
#include "utils.h"
#include "vm.h"
#include "gdbstub.h"
#include "guest_inspector.h"
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <linux/kvm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>

uint8_t break_instr = 0xcc;

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
    
    /* AVX YMM registers */
    GDB_CPU_X86_64_REG_YMM0    = 57,
    GDB_CPU_X86_64_REG_YMM1    = 58,
    GDB_CPU_X86_64_REG_YMM2    = 59,
    GDB_CPU_X86_64_REG_YMM3    = 60,
    GDB_CPU_X86_64_REG_YMM4    = 61,
    GDB_CPU_X86_64_REG_YMM5    = 62,
    GDB_CPU_X86_64_REG_YMM6    = 63,
    GDB_CPU_X86_64_REG_YMM7    = 64,
    GDB_CPU_X86_64_REG_YMM8    = 65,
    GDB_CPU_X86_64_REG_YMM9    = 66,
    GDB_CPU_X86_64_REG_YMM10   = 67,
    GDB_CPU_X86_64_REG_YMM11   = 68,
    GDB_CPU_X86_64_REG_YMM12   = 69,
    GDB_CPU_X86_64_REG_YMM13   = 70,
    GDB_CPU_X86_64_REG_YMM14   = 71,
    GDB_CPU_X86_64_REG_YMM15   = 72,
    
    GDB_CPU_X86_64_REG_COUNT   = 73
};

size_t indexes[] = {
    0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 
    80, 88, 96, 104, 112, 120, 128, 136, 
    140, 144, 148, 152, 156, 160, 164, 174, 
    184, 194, 204, 214, 224, 234, 244, 248, 
    252, 256, 260, 264, 268, 272, 276, 292, 
    308, 324, 340, 356, 372, 388, 404, 420, 
    436, 452, 468, 484, 500, 516, 532, 536, 
    552, 568, 584, 600, 616, 632, 648, 664, 
    680, 696, 712, 728, 744, 760, 776
};

void read_regs(struct debug_args* debug_args) {
    struct kvm_regs regs;
    if (ioctl(debug_args->vm->vcpufd, KVM_GET_REGS, &regs) < 0) {
        panic("KVM_GET_REGS");
    }
    struct kvm_sregs2 sregs;
    if (ioctl(debug_args->vm->vcpufd, KVM_GET_SREGS2, &sregs) < 0) {
        panic("KVM_GET_SREGS2");
    }

    struct kvm_fpu fpu;
    if (ioctl(debug_args->vm->vcpufd, KVM_GET_FPU, &fpu) < 0) {
        panic("KVM_GET_FPU");
    }

    uint8_t* regarray = debug_args->regs;

    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_RAX]],       &regs.rax, x86_64_regs_size[GDB_CPU_X86_64_REG_RAX]);     
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_RBX]],       &regs.rbx, x86_64_regs_size[GDB_CPU_X86_64_REG_RBX]);     
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_RCX]],       &regs.rcx, x86_64_regs_size[GDB_CPU_X86_64_REG_RCX]);     
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_RDX]],       &regs.rdx, x86_64_regs_size[GDB_CPU_X86_64_REG_RDX]);     
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_RSI]],       &regs.rsi, x86_64_regs_size[GDB_CPU_X86_64_REG_RSI]);     
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_RDI]],       &regs.rdi, x86_64_regs_size[GDB_CPU_X86_64_REG_RDI]);     
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_RBP]],       &regs.rbp, x86_64_regs_size[GDB_CPU_X86_64_REG_RBP]);     
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_RSP]],       &regs.rsp, x86_64_regs_size[GDB_CPU_X86_64_REG_RSP]);     
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_R8]],        &regs.r8, x86_64_regs_size[GDB_CPU_X86_64_REG_R8]);      
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_R9]],        &regs.r9, x86_64_regs_size[GDB_CPU_X86_64_REG_R9]);      
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_R10]],       &regs.r10, x86_64_regs_size[GDB_CPU_X86_64_REG_R10]);     
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_R11]],       &regs.r11, x86_64_regs_size[GDB_CPU_X86_64_REG_R11]);     
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_R12]],       &regs.r12, x86_64_regs_size[GDB_CPU_X86_64_REG_R12]);     
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_R13]],       &regs.r13, x86_64_regs_size[GDB_CPU_X86_64_REG_R13]);     
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_R14]],       &regs.r14, x86_64_regs_size[GDB_CPU_X86_64_REG_R14]);     
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_R15]],       &regs.r15, x86_64_regs_size[GDB_CPU_X86_64_REG_R15]);     
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_RIP]],       &regs.rip, x86_64_regs_size[GDB_CPU_X86_64_REG_RIP]);     
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_EFLAGS]],    &regs.rflags, x86_64_regs_size[GDB_CPU_X86_64_REG_EFLAGS]);  
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_CS]],        &sregs.cs.base, x86_64_regs_size[GDB_CPU_X86_64_REG_CS]);      
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_SS]],        &sregs.ss.base, x86_64_regs_size[GDB_CPU_X86_64_REG_SS]);      
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_DS]],        &sregs.ds.base, x86_64_regs_size[GDB_CPU_X86_64_REG_DS]);      
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_ES]],        &sregs.es.base, x86_64_regs_size[GDB_CPU_X86_64_REG_ES]);      
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_FS]],        &sregs.fs.base, x86_64_regs_size[GDB_CPU_X86_64_REG_FS]);      
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_GS]],        &sregs.gs.base, x86_64_regs_size[GDB_CPU_X86_64_REG_GS]);      
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_ST0]],       &fpu.fpr[0], x86_64_regs_size[GDB_CPU_X86_64_REG_ST0]);     
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_ST1]],       &fpu.fpr[1], x86_64_regs_size[GDB_CPU_X86_64_REG_ST1]);     
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_ST2]],       &fpu.fpr[2], x86_64_regs_size[GDB_CPU_X86_64_REG_ST2]);     
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_ST3]],       &fpu.fpr[3], x86_64_regs_size[GDB_CPU_X86_64_REG_ST3]);     
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_ST4]],       &fpu.fpr[4], x86_64_regs_size[GDB_CPU_X86_64_REG_ST4]);     
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_ST5]],       &fpu.fpr[5], x86_64_regs_size[GDB_CPU_X86_64_REG_ST5]);     
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_ST6]],       &fpu.fpr[6], x86_64_regs_size[GDB_CPU_X86_64_REG_ST6]);     
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_ST7]],       &fpu.fpr[7], x86_64_regs_size[GDB_CPU_X86_64_REG_ST7]);     
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_FCTRL]],     &fpu.fcw, x86_64_regs_size[GDB_CPU_X86_64_REG_FCTRL]);   
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_FSTAT]],     &fpu.fsw, x86_64_regs_size[GDB_CPU_X86_64_REG_FSTAT]);   
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_FTAG]],      &fpu.ftwx, x86_64_regs_size[GDB_CPU_X86_64_REG_FTAG]);    
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_FIOFF]],     &fpu.last_ip, x86_64_regs_size[GDB_CPU_X86_64_REG_FIOFF]);   
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_FOOFF]],     &fpu.last_dp, x86_64_regs_size[GDB_CPU_X86_64_REG_FOOFF]);   
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_FOP]],       &fpu.last_opcode, x86_64_regs_size[GDB_CPU_X86_64_REG_FOP]);     
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_XMM0]],      fpu.xmm[0], x86_64_regs_size[GDB_CPU_X86_64_REG_XMM0]);    
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_XMM1]],      fpu.xmm[1], x86_64_regs_size[GDB_CPU_X86_64_REG_XMM1]);    
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_XMM2]],      fpu.xmm[2], x86_64_regs_size[GDB_CPU_X86_64_REG_XMM2]);    
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_XMM3]],      fpu.xmm[3], x86_64_regs_size[GDB_CPU_X86_64_REG_XMM3]);    
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_XMM4]],      fpu.xmm[4], x86_64_regs_size[GDB_CPU_X86_64_REG_XMM4]);    
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_XMM5]],      fpu.xmm[5], x86_64_regs_size[GDB_CPU_X86_64_REG_XMM5]);    
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_XMM6]],      fpu.xmm[6], x86_64_regs_size[GDB_CPU_X86_64_REG_XMM6]);    
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_XMM7]],      fpu.xmm[7], x86_64_regs_size[GDB_CPU_X86_64_REG_XMM7]);    
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_XMM8]],      fpu.xmm[8], x86_64_regs_size[GDB_CPU_X86_64_REG_XMM8]);    
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_XMM9]],      fpu.xmm[9], x86_64_regs_size[GDB_CPU_X86_64_REG_XMM9]);    
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_XMM10]],     fpu.xmm[10], x86_64_regs_size[GDB_CPU_X86_64_REG_XMM10]);   
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_XMM11]],     fpu.xmm[11], x86_64_regs_size[GDB_CPU_X86_64_REG_XMM11]);   
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_XMM12]],     fpu.xmm[12], x86_64_regs_size[GDB_CPU_X86_64_REG_XMM12]);   
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_XMM13]],     fpu.xmm[13], x86_64_regs_size[GDB_CPU_X86_64_REG_XMM13]);   
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_XMM14]],     fpu.xmm[14], x86_64_regs_size[GDB_CPU_X86_64_REG_XMM14]);   
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_XMM15]],     fpu.xmm[15], x86_64_regs_size[GDB_CPU_X86_64_REG_XMM15]);   
    memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_MXCSR]],     &fpu.mxcsr, x86_64_regs_size[GDB_CPU_X86_64_REG_MXCSR]);
    //memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_FISEG]], 0, x86_64_regs_size[GDB_CPU_X86_64_REG_FISEG]);   
    //memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_FOSEG]], 0, x86_64_regs_size[GDB_CPU_X86_64_REG_FOSEG]);
    //avx512 not supported   
    //memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_YMM0]],  fpu.xmm[0], x86_64_regs_size[GDB_CPU_X86_64_REG_YMM0]);    
    //memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_YMM1]],  fpu.xmm[1], x86_64_regs_size[GDB_CPU_X86_64_REG_YMM1]);    
    //memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_YMM2]],  fpu.xmm[2], x86_64_regs_size[GDB_CPU_X86_64_REG_YMM2]);    
    //memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_YMM3]],  fpu.xmm[3], x86_64_regs_size[GDB_CPU_X86_64_REG_YMM3]);    
    //memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_YMM4]],  fpu.xmm[4], x86_64_regs_size[GDB_CPU_X86_64_REG_YMM4]);    
    //memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_YMM5]],  fpu.xmm[5], x86_64_regs_size[GDB_CPU_X86_64_REG_YMM5]);    
    //memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_YMM6]],  fpu.xmm[6], x86_64_regs_size[GDB_CPU_X86_64_REG_YMM6]);    
    //memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_YMM7]],  fpu.xmm[7], x86_64_regs_size[GDB_CPU_X86_64_REG_YMM7]);    
    //memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_YMM8]],  fpu.xmm[8], x86_64_regs_size[GDB_CPU_X86_64_REG_YMM8]);    
    //memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_YMM9]],  fpu.xmm[9], x86_64_regs_size[GDB_CPU_X86_64_REG_YMM9]);    
    //memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_YMM10]], fpu.xmm[10], x86_64_regs_size[GDB_CPU_X86_64_REG_YMM10]);   
    //memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_YMM11]], fpu.xmm[11], x86_64_regs_size[GDB_CPU_X86_64_REG_YMM11]);   
    //memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_YMM12]], fpu.xmm[12], x86_64_regs_size[GDB_CPU_X86_64_REG_YMM12]);   
    //memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_YMM13]], fpu.xmm[13], x86_64_regs_size[GDB_CPU_X86_64_REG_YMM13]);   
    //memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_YMM14]], fpu.xmm[14], x86_64_regs_size[GDB_CPU_X86_64_REG_YMM14]);   
    //memcpy(&regarray[indexes[GDB_CPU_X86_64_REG_YMM15]], fpu.xmm[15], x86_64_regs_size[GDB_CPU_X86_64_REG_YMM15]);   
}

void write_regs(struct debug_args* debug_args) {
    uint8_t* regarray = debug_args->regs;

    struct kvm_regs regs;
    if (ioctl(debug_args->vm->vcpufd, KVM_GET_REGS, &regs) < 0) {
        panic("KVM_GET_REGS");
    }
    struct kvm_sregs2 sregs;
    if (ioctl(debug_args->vm->vcpufd, KVM_GET_SREGS2, &sregs) < 0) {
        panic("KVM_GET_SREGS2");
    }

    struct kvm_fpu fpu;
    if (ioctl(debug_args->vm->vcpufd, KVM_GET_FPU, &fpu) < 0) {
        panic("KVM_GET_FPU");
    }

    memcpy(&regs.rax,   &regarray[indexes[GDB_CPU_X86_64_REG_RAX]], x86_64_regs_size[GDB_CPU_X86_64_REG_RAX]);     
    memcpy(&regs.rbx,   &regarray[indexes[GDB_CPU_X86_64_REG_RBX]], x86_64_regs_size[GDB_CPU_X86_64_REG_RBX]);     
    memcpy(&regs.rcx,   &regarray[indexes[GDB_CPU_X86_64_REG_RCX]], x86_64_regs_size[GDB_CPU_X86_64_REG_RCX]);     
    memcpy(&regs.rdx,   &regarray[indexes[GDB_CPU_X86_64_REG_RDX]], x86_64_regs_size[GDB_CPU_X86_64_REG_RDX]);     
    memcpy(&regs.rsi,   &regarray[indexes[GDB_CPU_X86_64_REG_RSI]], x86_64_regs_size[GDB_CPU_X86_64_REG_RSI]);     
    memcpy(&regs.rdi,   &regarray[indexes[GDB_CPU_X86_64_REG_RDI]], x86_64_regs_size[GDB_CPU_X86_64_REG_RDI]);     
    memcpy(&regs.rbp,   &regarray[indexes[GDB_CPU_X86_64_REG_RBP]], x86_64_regs_size[GDB_CPU_X86_64_REG_RBP]);     
    memcpy(&regs.rsp,   &regarray[indexes[GDB_CPU_X86_64_REG_RSP]], x86_64_regs_size[GDB_CPU_X86_64_REG_RSP]);     
    memcpy(&regs.r8,    &regarray[indexes[GDB_CPU_X86_64_REG_R8]] , x86_64_regs_size[GDB_CPU_X86_64_REG_R8]);      
    memcpy(&regs.r9,    &regarray[indexes[GDB_CPU_X86_64_REG_R9]] , x86_64_regs_size[GDB_CPU_X86_64_REG_R9]);      
    memcpy(&regs.r10,   &regarray[indexes[GDB_CPU_X86_64_REG_R10]], x86_64_regs_size[GDB_CPU_X86_64_REG_R10]);     
    memcpy(&regs.r11,   &regarray[indexes[GDB_CPU_X86_64_REG_R11]], x86_64_regs_size[GDB_CPU_X86_64_REG_R11]);     
    memcpy(&regs.r12,   &regarray[indexes[GDB_CPU_X86_64_REG_R12]], x86_64_regs_size[GDB_CPU_X86_64_REG_R12]);     
    memcpy(&regs.r13,   &regarray[indexes[GDB_CPU_X86_64_REG_R13]], x86_64_regs_size[GDB_CPU_X86_64_REG_R13]);     
    memcpy(&regs.r14,   &regarray[indexes[GDB_CPU_X86_64_REG_R14]], x86_64_regs_size[GDB_CPU_X86_64_REG_R14]);     
    memcpy(&regs.r15,   &regarray[indexes[GDB_CPU_X86_64_REG_R15]], x86_64_regs_size[GDB_CPU_X86_64_REG_R15]);     
    memcpy(&regs.rip,   &regarray[indexes[GDB_CPU_X86_64_REG_RIP]], x86_64_regs_size[GDB_CPU_X86_64_REG_RIP]);     
    memcpy(&regs.rflags, &regarray[indexes[GDB_CPU_X86_64_REG_EFLAGS]]    , x86_64_regs_size[GDB_CPU_X86_64_REG_EFLAGS]);  
    memcpy(&sregs.cs.base ,&regarray[indexes[GDB_CPU_X86_64_REG_CS]], x86_64_regs_size[GDB_CPU_X86_64_REG_CS]);      
    memcpy(&sregs.ss.base ,&regarray[indexes[GDB_CPU_X86_64_REG_SS]], x86_64_regs_size[GDB_CPU_X86_64_REG_SS]);      
    memcpy(&sregs.ds.base ,&regarray[indexes[GDB_CPU_X86_64_REG_DS]], x86_64_regs_size[GDB_CPU_X86_64_REG_DS]);      
    memcpy(&sregs.es.base ,&regarray[indexes[GDB_CPU_X86_64_REG_ES]], x86_64_regs_size[GDB_CPU_X86_64_REG_ES]);      
    memcpy(&sregs.fs.base ,&regarray[indexes[GDB_CPU_X86_64_REG_FS]], x86_64_regs_size[GDB_CPU_X86_64_REG_FS]);      
    memcpy(&sregs.gs.base ,&regarray[indexes[GDB_CPU_X86_64_REG_GS]], x86_64_regs_size[GDB_CPU_X86_64_REG_GS]);      
    memcpy(&fpu.fpr[0] ,&regarray[indexes[GDB_CPU_X86_64_REG_ST0]], x86_64_regs_size[GDB_CPU_X86_64_REG_ST0]);     
    memcpy(&fpu.fpr[1] ,&regarray[indexes[GDB_CPU_X86_64_REG_ST1]], x86_64_regs_size[GDB_CPU_X86_64_REG_ST1]);     
    memcpy(&fpu.fpr[2] ,&regarray[indexes[GDB_CPU_X86_64_REG_ST2]], x86_64_regs_size[GDB_CPU_X86_64_REG_ST2]);     
    memcpy(&fpu.fpr[3] ,&regarray[indexes[GDB_CPU_X86_64_REG_ST3]], x86_64_regs_size[GDB_CPU_X86_64_REG_ST3]);     
    memcpy(&fpu.fpr[4] ,&regarray[indexes[GDB_CPU_X86_64_REG_ST4]], x86_64_regs_size[GDB_CPU_X86_64_REG_ST4]);     
    memcpy(&fpu.fpr[5] ,&regarray[indexes[GDB_CPU_X86_64_REG_ST5]], x86_64_regs_size[GDB_CPU_X86_64_REG_ST5]);     
    memcpy(&fpu.fpr[6] ,&regarray[indexes[GDB_CPU_X86_64_REG_ST6]], x86_64_regs_size[GDB_CPU_X86_64_REG_ST6]);     
    memcpy(&fpu.fpr[7] ,&regarray[indexes[GDB_CPU_X86_64_REG_ST7]], x86_64_regs_size[GDB_CPU_X86_64_REG_ST7]);     
    memcpy(&fpu.fcw ,&regarray[indexes[GDB_CPU_X86_64_REG_FCTRL]], x86_64_regs_size[GDB_CPU_X86_64_REG_FCTRL]);   
    memcpy(&fpu.fsw ,&regarray[indexes[GDB_CPU_X86_64_REG_FSTAT]], x86_64_regs_size[GDB_CPU_X86_64_REG_FSTAT]);   
    memcpy(&fpu.ftwx ,&regarray[indexes[GDB_CPU_X86_64_REG_FTAG]] , x86_64_regs_size[GDB_CPU_X86_64_REG_FTAG]);    
    memcpy(&fpu.last_ip ,&regarray[indexes[GDB_CPU_X86_64_REG_FIOFF]], x86_64_regs_size[GDB_CPU_X86_64_REG_FIOFF]);   
    memcpy(&fpu.last_dp ,&regarray[indexes[GDB_CPU_X86_64_REG_FOOFF]], x86_64_regs_size[GDB_CPU_X86_64_REG_FOOFF]);   
    memcpy(&fpu.last_opcode ,&regarray[indexes[GDB_CPU_X86_64_REG_FOP]]  , x86_64_regs_size[GDB_CPU_X86_64_REG_FOP]);     
    memcpy(fpu.xmm[0] ,&regarray[indexes[GDB_CPU_X86_64_REG_XMM0]] , x86_64_regs_size[GDB_CPU_X86_64_REG_XMM0]);    
    memcpy(fpu.xmm[1] ,&regarray[indexes[GDB_CPU_X86_64_REG_XMM1]] , x86_64_regs_size[GDB_CPU_X86_64_REG_XMM1]);    
    memcpy(fpu.xmm[2] ,&regarray[indexes[GDB_CPU_X86_64_REG_XMM2]] , x86_64_regs_size[GDB_CPU_X86_64_REG_XMM2]);    
    memcpy(fpu.xmm[3] ,&regarray[indexes[GDB_CPU_X86_64_REG_XMM3]] , x86_64_regs_size[GDB_CPU_X86_64_REG_XMM3]);    
    memcpy(fpu.xmm[4] ,&regarray[indexes[GDB_CPU_X86_64_REG_XMM4]] , x86_64_regs_size[GDB_CPU_X86_64_REG_XMM4]);    
    memcpy(fpu.xmm[5] ,&regarray[indexes[GDB_CPU_X86_64_REG_XMM5]] , x86_64_regs_size[GDB_CPU_X86_64_REG_XMM5]);    
    memcpy(fpu.xmm[6] ,&regarray[indexes[GDB_CPU_X86_64_REG_XMM6]] , x86_64_regs_size[GDB_CPU_X86_64_REG_XMM6]);    
    memcpy(fpu.xmm[7] ,&regarray[indexes[GDB_CPU_X86_64_REG_XMM7]] , x86_64_regs_size[GDB_CPU_X86_64_REG_XMM7]);    
    memcpy(fpu.xmm[8] ,&regarray[indexes[GDB_CPU_X86_64_REG_XMM8]] , x86_64_regs_size[GDB_CPU_X86_64_REG_XMM8]);    
    memcpy(fpu.xmm[9] ,&regarray[indexes[GDB_CPU_X86_64_REG_XMM9]] , x86_64_regs_size[GDB_CPU_X86_64_REG_XMM9]);    
    memcpy(fpu.xmm[10] ,&regarray[indexes[GDB_CPU_X86_64_REG_XMM10]], x86_64_regs_size[GDB_CPU_X86_64_REG_XMM10]);   
    memcpy(fpu.xmm[11] ,&regarray[indexes[GDB_CPU_X86_64_REG_XMM11]], x86_64_regs_size[GDB_CPU_X86_64_REG_XMM11]);   
    memcpy(fpu.xmm[12] ,&regarray[indexes[GDB_CPU_X86_64_REG_XMM12]], x86_64_regs_size[GDB_CPU_X86_64_REG_XMM12]);   
    memcpy(fpu.xmm[13] ,&regarray[indexes[GDB_CPU_X86_64_REG_XMM13]], x86_64_regs_size[GDB_CPU_X86_64_REG_XMM13]);   
    memcpy(fpu.xmm[14] ,&regarray[indexes[GDB_CPU_X86_64_REG_XMM14]], x86_64_regs_size[GDB_CPU_X86_64_REG_XMM14]);   
    memcpy(fpu.xmm[15] ,&regarray[indexes[GDB_CPU_X86_64_REG_XMM15]], x86_64_regs_size[GDB_CPU_X86_64_REG_XMM15]);   
    memcpy(&fpu.mxcsr, &regarray[indexes[GDB_CPU_X86_64_REG_MXCSR]], x86_64_regs_size[GDB_CPU_X86_64_REG_MXCSR]);

    if (ioctl(debug_args->vm->vcpufd, KVM_SET_REGS, &regs) < 0) {
        panic("KVM_SET_REGS");
    }
    if (ioctl(debug_args->vm->vcpufd, KVM_SET_SREGS2, &sregs) < 0) {
        panic("KVM_SET_SREGS2");
    }
    if (ioctl(debug_args->vm->vcpufd, KVM_SET_FPU, &fpu) < 0) {
        panic("KVM_SET_FPU");
    }
}

static int read_reg(void *args, int regno, void *reg_value) {
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
            memcpy(reg_value, &regs.rax, x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_RBX:
            memcpy(reg_value, &regs.rbx, x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_RCX:
            memcpy(reg_value, &regs.rcx, x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_RDX:
            memcpy(reg_value, &regs.rdx, x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_RSI:
            memcpy(reg_value, &regs.rsi, x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_RDI:
            memcpy(reg_value, &regs.rdi, x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_RBP:
            memcpy(reg_value, &regs.rbp, x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_RSP:
            memcpy(reg_value, &regs.rsp, x86_64_regs_size[regno]);
            return 0;
            
        /* Additional 64-bit registers */
        case GDB_CPU_X86_64_REG_R8:
            memcpy(reg_value, &regs.r8, x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_R9:
            memcpy(reg_value, &regs.r9, x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_R10:
            memcpy(reg_value, &regs.r10, x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_R11:
            memcpy(reg_value, &regs.r11, x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_R12:
            memcpy(reg_value, &regs.r12, x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_R13:
            memcpy(reg_value, &regs.r13, x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_R14:
            memcpy(reg_value, &regs.r14, x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_R15:
            memcpy(reg_value, &regs.r15, x86_64_regs_size[regno]);
            return 0;
            
        /* Instruction pointer */
        case GDB_CPU_X86_64_REG_RIP:
            memcpy(reg_value, &regs.rip, x86_64_regs_size[regno]);
            return 0;
            
        /* Flags register */
        case GDB_CPU_X86_64_REG_EFLAGS:
            memcpy(reg_value, &regs.rflags, x86_64_regs_size[regno]);
            return 0;
            
        /* Segment registers */
        case GDB_CPU_X86_64_REG_CS:
            memcpy(reg_value, &sregs.cs.selector, x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_SS:
            memcpy(reg_value, &sregs.ss.selector, x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_DS:
            memcpy(reg_value, &sregs.ds.selector, x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_ES:
            memcpy(reg_value, &sregs.es.selector, x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_FS:
            memcpy(reg_value, &sregs.fs.selector, x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_GS:
            memcpy(reg_value, &sregs.gs.selector, x86_64_regs_size[regno]);
            return 0;
            
        /* FPU ST registers (80-bit floating point) */
        case GDB_CPU_X86_64_REG_ST0:
            memcpy(reg_value, &fpu.fpr[0], x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_ST1:
            memcpy(reg_value, &fpu.fpr[1], x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_ST2:
            memcpy(reg_value, &fpu.fpr[2], x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_ST3:
            memcpy(reg_value, &fpu.fpr[3], x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_ST4:
            memcpy(reg_value, &fpu.fpr[4], x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_ST5:
            memcpy(reg_value, &fpu.fpr[5], x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_ST6:
            memcpy(reg_value, &fpu.fpr[6], x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_ST7:
            memcpy(reg_value, &fpu.fpr[7], x86_64_regs_size[regno]);
            return 0;
            
        /* FPU control registers */
        case GDB_CPU_X86_64_REG_FCTRL:
            memcpy(reg_value, &fpu.fcw, x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_FSTAT:
            memcpy(reg_value, &fpu.fsw, x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_FTAG:
            memcpy(reg_value, &fpu.ftwx, x86_64_regs_size[regno]);
            return 0;
            case GDB_CPU_X86_64_REG_FISEG:
            // KVM doesn't expose code segment for FPU, use 0
            memset(reg_value, 0, x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_FIOFF:
            // Use last_ip (instruction pointer)
            memcpy(reg_value, &fpu.last_ip, x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_FOSEG:
            // KVM doesn't expose data segment for FPU, use 0
            memset(reg_value, 0, x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_FOOFF:
            // Use last_dp (data pointer)
            memcpy(reg_value, &fpu.last_dp, x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_FOP:
            // Use last_opcode
            memcpy(reg_value, &fpu.last_opcode, x86_64_regs_size[regno]);
            return 0;
            
        /* SSE registers (XMM) */
        case GDB_CPU_X86_64_REG_XMM0:
            memcpy(reg_value, &fpu.xmm[0], x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_XMM1:
            memcpy(reg_value, &fpu.xmm[1], x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_XMM2:
            memcpy(reg_value, &fpu.xmm[2], x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_XMM3:
            memcpy(reg_value, &fpu.xmm[3], x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_XMM4:
            memcpy(reg_value, &fpu.xmm[4], x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_XMM5:
            memcpy(reg_value, &fpu.xmm[5], x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_XMM6:
            memcpy(reg_value, &fpu.xmm[6], x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_XMM7:
            memcpy(reg_value, &fpu.xmm[7], x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_XMM8:
            memcpy(reg_value, &fpu.xmm[8], x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_XMM9:
            memcpy(reg_value, &fpu.xmm[9], x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_XMM10:
            memcpy(reg_value, &fpu.xmm[10], x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_XMM11:
            memcpy(reg_value, &fpu.xmm[11], x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_XMM12:
            memcpy(reg_value, &fpu.xmm[12], x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_XMM13:
            memcpy(reg_value, &fpu.xmm[13], x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_XMM14:
            memcpy(reg_value, &fpu.xmm[14], x86_64_regs_size[regno]);
            return 0;
        case GDB_CPU_X86_64_REG_XMM15:
            memcpy(reg_value, &fpu.xmm[15], x86_64_regs_size[regno]);
            return 0;
            
        /* SSE control register */
        case GDB_CPU_X86_64_REG_MXCSR:
            memcpy(reg_value, &fpu.mxcsr, x86_64_regs_size[regno]);
            return 0;
            
        /*
        default:
            return EFAULT;
        */
        default:
            memset(reg_value, 0, x86_64_regs_size[regno]); // not supported -> write 0
            return 0;
    }
    return 0;
}

static int write_reg(void *args, int regno, void* data) {
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
            memcpy(&regs.rax, data, x86_64_regs_size[regno]);
            break;
        case GDB_CPU_X86_64_REG_RBX:
            memcpy(&regs.rbx, data, x86_64_regs_size[regno]);
            break;
        case GDB_CPU_X86_64_REG_RCX:
            memcpy(&regs.rcx, data, x86_64_regs_size[regno]);
            break;
        case GDB_CPU_X86_64_REG_RDX:
            memcpy(&regs.rdx, data, x86_64_regs_size[regno]);
            break;
        case GDB_CPU_X86_64_REG_RSI:
            memcpy(&regs.rsi, data, x86_64_regs_size[regno]);
            break;
        case GDB_CPU_X86_64_REG_RDI:
            memcpy(&regs.rdi, data, x86_64_regs_size[regno]);
            break;
        case GDB_CPU_X86_64_REG_RBP:
            memcpy(&regs.rbp, data, x86_64_regs_size[regno]);
            break;
        case GDB_CPU_X86_64_REG_RSP:
            memcpy(&regs.rsp, data, x86_64_regs_size[regno]);
            break;
            
        /* Additional 64-bit registers */
        case GDB_CPU_X86_64_REG_R8:
            memcpy(&regs.r8, data, x86_64_regs_size[regno]);
            break;
        case GDB_CPU_X86_64_REG_R9:
            memcpy(&regs.r9, data, x86_64_regs_size[regno]);
            break;
        case GDB_CPU_X86_64_REG_R10:
            memcpy(&regs.r10, data, x86_64_regs_size[regno]);
            break;
        case GDB_CPU_X86_64_REG_R11:
            memcpy(&regs.r11, data, x86_64_regs_size[regno]);
            break;
        case GDB_CPU_X86_64_REG_R12:
            memcpy(&regs.r12, data, x86_64_regs_size[regno]);
            break;
        case GDB_CPU_X86_64_REG_R13:
            memcpy(&regs.r13, data, x86_64_regs_size[regno]);
            break;
        case GDB_CPU_X86_64_REG_R14:
            memcpy(&regs.r15, data, x86_64_regs_size[regno]);
            break;
        case GDB_CPU_X86_64_REG_R15:
            memcpy(&regs.r15, data, x86_64_regs_size[regno]);
            break;
            
        /* Instruction pointer */
        case GDB_CPU_X86_64_REG_RIP:
            memcpy(&regs.rip, data, x86_64_regs_size[regno]);
            break;
            
        /* Flags register */
        case GDB_CPU_X86_64_REG_EFLAGS:
            memcpy(&regs.rflags, data, x86_64_regs_size[regno]);
            break;
        default:
            break;
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

int memory_with_breakpoints(struct breakpoint breakpoints[], uint8_t* buff, size_t addr, size_t len) {
    for (int i = 0; i < BREAKPOINTS_MAX_NUM; i++) {
        struct breakpoint* bp = &breakpoints[i];
        // this breakpoint is in that memory -> set it
        if (bp->addr >= addr && bp->addr < addr + len) {
            buff[bp->addr - addr] = break_instr;
        }
    }
    return 0;
}

int memory_without_breakpoints(struct breakpoint breakpoints[], uint8_t* buff, size_t addr, size_t len) {
    for (int i = 0; i < BREAKPOINTS_MAX_NUM; i++) {
        struct breakpoint* bp = &breakpoints[i];
        // this breakpoint is in that memory -> set it
        if (bp->addr >= addr && bp->addr < addr + len) {
            buff[bp->addr - addr] = bp->original_data;
        }
    }
    return 0;
}

static int read_mem(void *args, size_t addr, size_t len, void *val) {
    printf("read_mem addr: %p, len: %ld\n", (void*)addr, len);
    struct debug_args* debug_args = (struct debug_args*)args;
    
    if (read_buffer_host(debug_args->vm, addr, val, len) < 0) {
        return EFAULT;
    }

    memory_without_breakpoints(debug_args->breakpoints, val, addr, len);

    return 0;
}

static int write_mem(void *args, size_t addr, size_t len, void *val) {
    printf("write_mem addr: %p, len: %ld\n", (void*)addr, len);
    struct debug_args* debug_args = (struct debug_args*)args;

    memory_with_breakpoints(debug_args->breakpoints, val, addr, len);

    if (write_buffer_guest(debug_args->vm, addr, val, len) < 0) {
        return EFAULT;
    }
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

    for (int i = 0; i < BREAKPOINTS_MAX_NUM; i++) {
        struct breakpoint* bp = &debug_args->breakpoints[i];
        // empyt breakpoint found
        if (bp->addr == 0) {
            bp->addr = addr;

            // read the origina data
            int ret = read_buffer_host(
                debug_args->vm, 
                addr, 
                &bp->original_data, 
                sizeof(bp->original_data)
            );
            if (ret < 0) return false; // cannot access memory

            // replace it with break_inst
            ret = write_buffer_guest(
                debug_args->vm, 
                addr, 
                &break_instr, 
                sizeof(break_instr)
            );
            if (ret < 0) return false; // cannot access memory

            return true;
        }
    }
    // max number of breakpoints reached
    return false;
}

static bool del_bp(void *args, size_t addr, bp_type_t type) {
    printf("del_bp addr: %p, type: %d\n", (void*)addr, type);
    struct debug_args* debug_args = (struct debug_args*)args;

    for (int i = 0; i < BREAKPOINTS_MAX_NUM; i++) {
        struct breakpoint* bp = &debug_args->breakpoints[i];
        // breakpoint found
        if (bp->addr == addr) {
            bp->addr = 0;

            // restore the instruction
            int ret = write_buffer_guest(
                debug_args->vm, 
                addr, 
                &bp->original_data, 
                sizeof(bp->original_data)
            );
            if (ret < 0) return false; // cannot access memory

            return true;
        }
    }

    // breakpoint does't exisits
    return false;
}

static void on_interrupt(void *args __attribute__((unused))) {
    printf("on_interrupt\n");
    //struct debug_args* debug_args = (struct debug_args*)args;
    
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
