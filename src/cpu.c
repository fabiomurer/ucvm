#include <asm/kvm.h>
#define _GNU_SOURCE

#include <stdint.h>
#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include "cpu.h"
#include "utils.h"
#include "gdt.h"
#include "idt.h"

typedef enum microarchitecture_level {
	x86_64_v1,
	x86_64_v2,
	x86_64_v3,
	x86_64_v4,
	x86_64_unknown
} microarchitecture_level;

microarchitecture_level cpu_microarchitecture_levels(struct kvm_cpuid2 *cpuid)
{
	// Feature flags
	bool has_cmov = false;
	bool has_cx8 = false;
	bool has_fpu = false;
	bool has_fxsr = false;
	bool has_mmx = false;
	bool has_syscall = false; // SCE (SYSCALL/SYSRET)
	bool has_sse = false;
	bool has_sse2 = false;

	bool has_cmpxchg16b = false;
	bool has_lahf_sahf = false;
	bool has_popcnt = false;
	bool has_sse3 = false;
	bool has_ssse3 = false;
	bool has_sse4_1 = false;
	bool has_sse4_2 = false;

	bool has_avx = false;
	bool has_avx2 = false;
	bool has_bmi1 = false;
	bool has_bmi2 = false;
	bool has_f16c = false;
	bool has_fma = false;
	bool has_lzcnt = false;
	bool has_movbe = false;
	bool has_xsave = false;

	bool has_avx512f = false;
	bool has_avx512bw = false;
	bool has_avx512cd = false;
	bool has_avx512dq = false;
	bool has_avx512vl = false;

	// KVM_GET_SUPPORTED_CPUID updates cpuid->nent with the actual number of entries filled.
	for (uint32_t i = 0; i < cpuid->nent; i++) {
		struct kvm_cpuid_entry2 *entry = &cpuid->entries[i];

		// Standard Features (Function 0x00000001)
		// For this leaf, index (ECX input) is not typically varied for these basic feature
		// flags.
		if (entry->function == 0x00000001 &&
		    !(entry->flags & KVM_CPUID_FLAG_SIGNIFCANT_INDEX)) {
			if (entry->edx & (1U << 0))
				has_fpu = true; // EDX[0]  FPU
			if (entry->edx & (1U << 8))
				has_cx8 = true; // EDX[8]  CMPXCHG8B
			if (entry->edx & (1U << 15))
				has_cmov = true; // EDX[15] CMOV
			if (entry->edx & (1U << 23))
				has_mmx = true; // EDX[23] MMX
			if (entry->edx & (1U << 24))
				has_fxsr = true; // EDX[24] FXSAVE/FXRSTOR
			if (entry->edx & (1U << 25))
				has_sse = true; // EDX[25] SSE
			if (entry->edx & (1U << 26))
				has_sse2 = true; // EDX[26] SSE2

			if (entry->ecx & (1U << 0))
				has_sse3 = true; // ECX[0]  SSE3
			if (entry->ecx & (1U << 9))
				has_ssse3 = true; // ECX[9]  SSSE3
			if (entry->ecx & (1U << 12))
				has_fma = true; // ECX[12] FMA3
			if (entry->ecx & (1U << 13))
				has_cmpxchg16b = true; // ECX[13] CMPXCHG16B
			if (entry->ecx & (1U << 19))
				has_sse4_1 = true; // ECX[19] SSE4.1
			if (entry->ecx & (1U << 20))
				has_sse4_2 = true; // ECX[20] SSE4.2
			if (entry->ecx & (1U << 22))
				has_movbe = true; // ECX[22] MOVBE
			if (entry->ecx & (1U << 23))
				has_popcnt = true; // ECX[23] POPCNT
			if (entry->ecx & (1U << 26))
				has_xsave = true; // ECX[26] XSAVE
			if (entry->ecx & (1U << 28))
				has_avx = true; // ECX[28] AVX
			if (entry->ecx & (1U << 29))
				has_f16c = true; // ECX[29] F16C (Half-precision convert)
		}

		// Structured Extended Features (Function 0x00000007, Index 0)
		// KVM_CPUID_FLAG_SIGNIFCANT_INDEX means the 'index' field was used as input ECX.
		if (entry->function == 0x00000007 &&
		    (entry->flags & KVM_CPUID_FLAG_SIGNIFCANT_INDEX) && entry->index == 0) {
			if (entry->ebx & (1U << 3))
				has_bmi1 = true; // EBX[3]  BMI1
			if (entry->ebx & (1U << 5))
				has_avx2 = true; // EBX[5]  AVX2
			if (entry->ebx & (1U << 8))
				has_bmi2 = true; // EBX[8]  BMI2
			if (entry->ebx & (1U << 16))
				has_avx512f = true; // EBX[16] AVX512F (Foundation)
			if (entry->ebx & (1U << 17))
				has_avx512dq = true; // EBX[17] AVX512DQ (Double/Quadword)
			if (entry->ebx & (1U << 28))
				has_avx512cd = true; // EBX[28] AVX512CD (Conflict Detection)
			if (entry->ebx & (1U << 30))
				has_avx512bw = true; // EBX[30] AVX512BW (Byte/Word)
			if (entry->ebx & (1U << 31))
				has_avx512vl = true; // EBX[31] AVX512VL (Vector Length Ext)
		}

		// Extended Features (Function 0x80000001)
		// Index is not typically varied for these flags.
		if (entry->function == 0x80000001 &&
		    !(entry->flags & KVM_CPUID_FLAG_SIGNIFCANT_INDEX)) {
			if (entry->ecx & (1U << 0))
				has_lahf_sahf = true; // ECX[0] LAHF/SAHF in 64-bit mode
			if (entry->ecx & (1U << 5))
				has_lzcnt = true; // ECX[5] LZCNT (ABM on AMD)
			if (entry->edx & (1U << 11))
				has_syscall = true; // EDX[11] SYSCALL/SYSRET
			// Note: CPUID.80000001h:EDX[20] is NX bit (No-Execute), not in the
			// microarch levels list but important. Note: CPUID.80000001h:EDX[29] is
			// Long Mode (x86-64), fundamental.
		}
	}

	bool v1_supported = has_cmov && has_cx8 && has_fpu && has_fxsr && has_mmx && has_syscall &&
			    has_sse && has_sse2;
	bool v2_supported = v1_supported && has_cmpxchg16b && has_lahf_sahf && has_popcnt &&
			    has_sse3 && has_sse4_1 && has_sse4_2 && has_ssse3;
	bool v3_supported = v2_supported && has_avx && has_avx2 && has_bmi1 && has_bmi2 &&
			    has_f16c && has_fma && has_lzcnt && has_movbe && has_xsave;
	bool v4_supported = v3_supported && has_avx512f && has_avx512bw && has_avx512cd &&
			    has_avx512dq && has_avx512vl;

#if DEBUG
	printf("Checking x86-64 microarchitecture levels:\n");
	printf("  x86-64-v1 (baseline) supported: %s\n", v1_supported ? "Yes" : "No");
	printf("  x86-64-v2 supported: %s\n", v2_supported ? "Yes" : "No");
	printf("  x86-64-v3 supported: %s\n", v3_supported ? "Yes" : "No");
	printf("  x86-64-v4 supported: %s\n", v4_supported ? "Yes" : "No");
#endif

	if (v4_supported) {
		return x86_64_v4;
	}
	if (v3_supported) {
		return x86_64_v3;
	}
	if (v2_supported) {
		return x86_64_v2;
	}
	if (v1_supported) {
		return x86_64_v1;
	}

	return x86_64_unknown;
}

void cpu_init_sse(struct kvm_sregs2 *sregs)
{
#define CR4_OSFXSR (1ULL << 9)
#define CR4_OSXMMEXCPT (1ULL << 10)
#define CR0_EM (1ULL << 2)
#define CR0_MP (1ULL << 1)

	// sse
	/*
	clear the CR0.EM bit (bit 2) [ CR0 &= ~(1 << 2) ]
	set the CR0.MP bit (bit 1) [ CR0 |= (1 << 1) ]
	set the CR4.OSFXSR bit (bit 9) [ CR4 |= (1 << 9) ]
	set the CR4.OSXMMEXCPT bit (bit 10) [ CR4 |= (1 << 10) ]
	*/
	sregs->cr0 &= ~CR0_EM;
	sregs->cr0 |= CR0_MP;
	sregs->cr4 |= CR4_OSFXSR;
	sregs->cr4 |= CR4_OSXMMEXCPT;
}

void cpu_init_fpu(struct kvm_fpu *fpu)
{
	/*
	FNINIT will reset the user-visible part of the FPU stack. This will set
	precision to 64-bit and rounding to nearest, which should be correct for
	most operations. It will also mask all exceptions from causing an
	interrupt.
	*/

// x87 FPU Control Word Flags
#define FCW_IM  (1 << 0)  // Invalid Operation Mask
#define FCW_DM  (1 << 1)  // Denormalized Operand Mask
#define FCW_ZM  (1 << 2)  // Zero Divide Mask
#define FCW_OM  (1 << 3)  // Overflow Mask
#define FCW_UM  (1 << 4)  // Underflow Mask
#define FCW_PM  (1 << 5)  // Precision Mask
#define FCW_PC  (3 << 8)  // Precision Control (11b = Double Precision)
#define FCW_RC  (0 << 10) // Rounding Control (00b = Round to Nearest)
#define FCW_X   (0 << 12) // Infinity Control (obsolete, always zero)

// x87 FPU Tag Word (8x2 bits, one per register)
// 0b11 (0x3) = Empty, 0b00 = Valid, 0b01 = Zero, 0b10 = Special
#define FTWX_ALL_EMPTY 0xFF  // All 8 registers empty (2 bits per reg, all set)

// MXCSR Exception Masks
#define MXCSR_PM (1UL << 12)
#define MXCSR_UM (1UL << 11)
#define MXCSR_OM (1UL << 10)
#define MXCSR_ZM (1UL << 9)
#define MXCSR_DM (1UL << 8)
#define MXCSR_IM (1UL << 7)

	fpu->fcw  = FCW_IM | FCW_DM | FCW_ZM | FCW_OM |
                FCW_UM | FCW_PM | FCW_PC | FCW_RC | FCW_X;
	fpu->ftwx = FTWX_ALL_EMPTY;
	fpu->mxcsr = MXCSR_PM |
		MXCSR_UM |
		MXCSR_OM |
		MXCSR_ZM |
		MXCSR_DM |
		MXCSR_IM;
}

void cpu_init_avx(struct kvm_sregs2 *sregs, struct kvm_xcrs *xrcs)
{
#define CR4_OSXSAVE (1ULL << 18)
#define CR4_FSGSBASE (1ULL << 16)

#define XCR0_X87 (1ULL << 0) // x87 FPU/MMX state (must be 1)
#define XCR0_SSE (1ULL << 1) // SSE state
#define XCR0_AVX (1ULL << 2) // AVX state

	// Both SSE and OSXSAVE must be enabled before allowing. Failing to do
	// so will also produce an #UD.
	sregs->cr4 |= CR4_OSXSAVE | CR4_FSGSBASE;

	for (uint32_t i = 0; i < xrcs->nr_xcrs; i++) {
		// found xcr0
		if (xrcs->xcrs[i].xcr == 0) {
			xrcs->xcrs[i].value |= XCR0_X87 | XCR0_SSE | XCR0_AVX;
			break;
		}
	}
}

void cpu_init_avx512(struct kvm_xcrs *xrcs)
{
#define XCR0_OPMASK (1LL << 5)
#define ZMM_Hi256 (1LL << 6)
#define Hi16_ZMM (1LL << 7)

	for (uint32_t i = 0; i < xrcs->nr_xcrs; i++) {
		// found xcr0
		if (xrcs->xcrs[i].xcr == 0) {
			xrcs->xcrs[i].value |= XCR0_OPMASK | ZMM_Hi256 | Hi16_ZMM;
			break;
		}
	}
}

/*
not all features are initialized for all levels
TODO: check if all expected features are enabled
*/

void cpu_init_v1(struct kvm_sregs2 *sregs, struct kvm_fpu *fpu)
{
	cpu_init_fpu(fpu);
	cpu_init_sse(sregs);
}

void cpu_init_v2(void)
{
	// SSE2 ... are automatically enabled if supported
	// nothing to do
}

void cpu_init_v3(struct kvm_sregs2 *sregs, struct kvm_xcrs *xrcs)
{
	cpu_init_avx(sregs, xrcs);
}

void cpu_init_v4(struct kvm_xcrs *xrcs)
{
	cpu_init_avx512(xrcs);
}

void cpu_init_cache(struct kvm_sregs2 *sregs)
{
// cache disabled
#define CR0_CD (1ULL << 30)
// not write_thorught
#define CR0_NW (1ULL << 29)

	// Clear CD (bit 30) and NW (bit 29) to enable caching
	sregs->cr0 &= ~(CR0_CD | CR0_NW);

	/*
	PAT is set to wb for all memory pages in vmm.c
	WB better for ram
	IA32_PAT (MSR 0x277) default value 0x0007040600070406
	Index	PAT	PCD	PWT	Value	Memory Type
	0	    0	0	0	0x06	Write-Back (WB)
	1	    0	0	1	0x04	Write-Through (WT)
	2	    0	1	0	0x07	Uncacheable-Minus (UC-)
	3	    0	1	1	0x00	Uncacheable (UC)
	4	    1	0	0	0x06	Write-Back (WB)
	5	    1	0	1	0x04	Write-Through (WT)
	6	    1	1	0	0x07	Uncacheable-Minus (UC-)
	7	    1	1	1	0x00	Uncacheable (UC)
	*/
}

void cpu_init_long(struct kvm_sregs2 *sregs, struct vmm *vmm)
{
#define CRO_PROTECTED_MODE (1ULL << 0)
#define CR0_ENABLE_PAGING (1ULL << 31)
#define CR4_ENABLE_PAE (1ULL << 5)
#define CR4_ENABLE_PGE (1ULL << 7)

/*
bit 10

Description: Indicates whether long mode is active. This bit is read-only and is
set by the processor when entering long mode.
- Values:
    - 0: Long mode is not active
    - 1: Long mode is active
*/
#define EFER_LONG_MODE_ENABLED (1ULL << 8)
#define EFER_LONG_MODE_ACTIVE (1ULL << 10)

/*
bit 11

Description: Enables the no-execute page protection feature, which prevents code
execution from data pages.

- Values:
    -0: No-execute page protection is disabled
    - 1: No-execute page protection is enabled
*/
#define EFER_NO_EXECUTE_ENABLE (1ULL << 11)

	sregs->cr0 |= CRO_PROTECTED_MODE | CR0_ENABLE_PAGING;
	sregs->cr3 = (uint64_t)vmm->pml4t_addr.guest_physical_addr;
	sregs->cr4 |= CR4_ENABLE_PAE | CR4_ENABLE_PGE;
	sregs->efer |= EFER_LONG_MODE_ENABLED | EFER_LONG_MODE_ACTIVE; // EFER_LONG_MODE_ENABLED??

	// initialize segments for long mode
	// code segment
	struct kvm_segment gdt_code_segment = gdt_get_segment(GDT_IDX_CODE);
	struct kvm_segment gdt_data_segment = gdt_get_segment(GDT_IDX_DATA);

	sregs->cs = gdt_code_segment;
	// data segment
	sregs->ds = gdt_data_segment;
	// stack segment
	sregs->ss = gdt_data_segment;
	// additional data and string operation
	sregs->es = gdt_data_segment;
	// thread-specific data structures
	sregs->fs = gdt_data_segment;
	// thread-specific data structures
	sregs->gs = gdt_data_segment;
}

void cpu_clear_regs(struct kvm_regs *regs)
{
	regs->rax = 0;
	regs->rbx = 0;
	regs->rcx = 0;
	regs->rdx = 0;
	regs->rsi = 0;
	regs->rdi = 0;
	regs->rbp = 0;
	regs->rsp = 0;
	regs->r8 = 0;
	regs->r9 = 0;
	regs->r10 = 0;
	regs->r11 = 0;
	regs->r12 = 0;
	regs->r13 = 0;
	regs->r14 = 0;
	regs->r15 = 0;
	regs->rip = 0;
	regs->rflags = 0;
}

void cpu_init(int vcpufd, struct kvm_cpuid2* vcpu_cpuid, struct vmm *vmm)
{

	microarchitecture_level vcpulevel = cpu_microarchitecture_levels(vcpu_cpuid);

	struct kvm_regs regs;
	struct kvm_sregs2 sregs;
	struct kvm_fpu fpu;
	struct kvm_xcrs xcrs;

	if (ioctl(vcpufd, KVM_GET_REGS, &regs) < 0) {
		PANIC_PERROR("KVM_GET_REGS");
	}
	if (ioctl(vcpufd, KVM_GET_SREGS2, &sregs) < 0) {
		PANIC_PERROR("KVM_GET_SREGS2");
	}
	if (ioctl(vcpufd, KVM_GET_FPU, &fpu) < 0) {
		PANIC_PERROR("KVM_GET_FPU");
	}
	if (ioctl(vcpufd, KVM_GET_XCRS, &xcrs) < 0) {
		PANIC_PERROR("KVM_GET_XCRS");
	}

	vmm_init(vmm);
	gdt_init(&sregs, vmm);
	idt_init(&sregs, vmm);
	cpu_init_long(&sregs, vmm);
	cpu_init_cache(&sregs);

	// TODO: make it better
	if (vcpulevel == x86_64_unknown) {
		PANIC("cpu not supported");
	}
	if (vcpulevel >= x86_64_v1) {
		cpu_init_v1(&sregs, &fpu);
	}
	if (vcpulevel >= x86_64_v2) {
		cpu_init_v2();
	}
	if (vcpulevel >= x86_64_v3) {
		cpu_init_v3(&sregs, &xcrs);
	}
	if (vcpulevel == x86_64_v4) {
		cpu_init_v4(&xcrs);
	}

	cpu_clear_regs(&regs);

	if (ioctl(vcpufd, KVM_SET_REGS, &regs) < 0) {
		PANIC_PERROR("KVM_SET_REGS");
	}
	if (ioctl(vcpufd, KVM_SET_SREGS2, &sregs) < 0) {
		PANIC_PERROR("KVM_SET_SREGS2");
	}
	if (ioctl(vcpufd, KVM_SET_FPU, &fpu) < 0) {
		PANIC_PERROR("KVM_SET_FPU");
	}
	if (ioctl(vcpufd, KVM_SET_XCRS, &xcrs) < 0) {
		PANIC_PERROR("KVM_SET_XCRS");
	}
}
