#define _GNU_SOURCE

#include <linux/kvm.h>
#include <sched.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <fcntl.h>

#include "vm.h"
#include "arguments.h"
#include "view_linux.h"
#include "utils.h"
#include "vminfo.h"
#include "vmm.h"
#include "vsyscall.h"
#include "guest_inspector.h"

#define KVM_DEVICE "/dev/kvm"

void vm_run_enable_sync_regs(struct vm *vm)
{
	// For x86, the ‘kvm_valid_regs’ field of struct kvm_run is overloaded to
	// function as an input bit-array field set by userspace to indicate the
	// specific register sets to be copied out on the next exit.
	vm->run->kvm_valid_regs = KVM_SYNC_X86_REGS | KVM_SYNC_X86_SREGS;
}

struct kvm_regs *vm_get_regs(struct vm *vm)
{
	if ((vm->run->kvm_valid_regs & KVM_SYNC_X86_REGS) == 0) {
		PANIC("REGS not valid");
	}

	return &vm->run->s.regs.regs;
}

struct kvm_sregs *vm_get_sregs(struct vm *vm)
{
	if ((vm->run->kvm_valid_regs & KVM_SYNC_X86_SREGS) == 0) {
		PANIC("REGS not valid");
	}

	return &vm->run->s.regs.sregs;
}

void vm_set_regs(struct vm *vm)
{
	// To indicate when userspace has modified values that should be copied into
	// the vCPU, the all architecture bitarray field, ‘kvm_dirty_regs’ must be set.
	// This is done using the same bitflags as for the ‘kvm_valid_regs’ field.
	vm->run->kvm_dirty_regs |= KVM_SYNC_X86_REGS;
}

void vm_set_sregs(struct vm *vm)
{
	vm->run->kvm_dirty_regs |= KVM_SYNC_X86_SREGS;
}

struct vm vm_create(void)
{
	struct vm vm = { 0 };
	vm.debug_enabled = false;

	// connect to kvm
	if ((vm.kvmfd = open(KVM_DEVICE, O_RDWR | O_CLOEXEC)) < 0) {
		PANIC_PERROR("Failed to open " KVM_DEVICE);
	}

	// Check KVM API version
	int api_version = ioctl(vm.kvmfd, KVM_GET_API_VERSION, 0);
	if (api_version == -1)
		PANIC_PERROR("KVM_GET_API_VERSION");
	if (api_version != 12) {
		PANIC("KVM API version not supported");
	}

	int supported_sync_regs = ioctl(vm.kvmfd, KVM_CHECK_EXTENSION, KVM_CAP_SYNC_REGS);
	if (supported_sync_regs != KVM_SYNC_X86_VALID_FIELDS) {
		PANIC("KVM_CAP_SYNC_REGS not supported");
	}

	// create a vm
	if ((vm.vmfd = ioctl(vm.kvmfd, KVM_CREATE_VM, 0)) < 0) {
		PANIC_PERROR("KVM_CREATE_VM");
	}

	// create vcpu
	ssize_t vcpu_mmap_size;
	if ((vcpu_mmap_size = ioctl(vm.kvmfd, KVM_GET_VCPU_MMAP_SIZE, 0)) <= 0) {
		PANIC_PERROR("KVM_GET_VCPU_MMAP_SIZE");
	}

	if ((vm.vcpufd = ioctl(vm.vmfd, KVM_CREATE_VCPU, 0)) < 0) {
		PANIC_PERROR("KVM_CREATE_VCPU");
	}

	if ((vm.run = mmap(NULL, vcpu_mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vm.vcpufd,
			   0)) == MAP_FAILED) {
		PANIC_PERROR("MMAP");
	}

	// pin the vcpu at one cop
	if (arguments.cpu_pin != -1) {
		cpu_set_t set;
		CPU_ZERO(&set);
		// pin to cpu 0
		CPU_SET(0, &set);

		if (sched_setaffinity(getpid(), sizeof(set), &set) == -1) {
			PANIC_PERROR("sched_setaffinity");
		}
	}

	// create memory
	if ((vm.memory = mmap(NULL, MEMORY_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS,
			      -1, 0)) == MAP_FAILED) {
		PANIC_PERROR("MMAP");
	}
	memset(vm.memory, 0, MEMORY_SIZE); // ?

	struct kvm_userspace_memory_region region = {
		.slot = MEMORY_SLOT,
		.flags = 0,
		.guest_phys_addr = GUEST_PHYS_ADDR,
		.memory_size = MEMORY_SIZE,
		.userspace_addr = (uint64_t)vm.memory,
	};

	if (ioctl(vm.vmfd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
		PANIC_PERROR("KVM_SET_USER_MEMORY_REGION");
	}

	return vm;
}

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
		// For this leaf, index (ECX input) is not typically varied for these basic feature flags.
		if (entry->function == 0x00000001 && !(entry->flags & KVM_CPUID_FLAG_SIGNIFCANT_INDEX)) {
			if (entry->edx & (1U << 0))  has_fpu = true;          // EDX[0]  FPU
			if (entry->edx & (1U << 8))  has_cx8 = true;          // EDX[8]  CMPXCHG8B
			if (entry->edx & (1U << 15)) has_cmov = true;        // EDX[15] CMOV
			if (entry->edx & (1U << 23)) has_mmx = true;         // EDX[23] MMX
			if (entry->edx & (1U << 24)) has_fxsr = true;        // EDX[24] FXSAVE/FXRSTOR
			if (entry->edx & (1U << 25)) has_sse = true;         // EDX[25] SSE
			if (entry->edx & (1U << 26)) has_sse2 = true;        // EDX[26] SSE2

			if (entry->ecx & (1U << 0)) has_sse3 = true;         // ECX[0]  SSE3
			if (entry->ecx & (1U << 9)) has_ssse3 = true;        // ECX[9]  SSSE3
			if (entry->ecx & (1U << 12)) has_fma = true;         // ECX[12] FMA3
			if (entry->ecx & (1U << 13)) has_cmpxchg16b = true;  // ECX[13] CMPXCHG16B
			if (entry->ecx & (1U << 19)) has_sse4_1 = true;      // ECX[19] SSE4.1
			if (entry->ecx & (1U << 20)) has_sse4_2 = true;      // ECX[20] SSE4.2
			if (entry->ecx & (1U << 22)) has_movbe = true;       // ECX[22] MOVBE
			if (entry->ecx & (1U << 23)) has_popcnt = true;      // ECX[23] POPCNT
			if (entry->ecx & (1U << 26)) has_xsave = true;     	 // ECX[26] XSAVE
			if (entry->ecx & (1U << 28)) has_avx = true;         // ECX[28] AVX
			if (entry->ecx & (1U << 29)) has_f16c = true;        // ECX[29] F16C (Half-precision convert)
		}

		// Structured Extended Features (Function 0x00000007, Index 0)
		// KVM_CPUID_FLAG_SIGNIFCANT_INDEX means the 'index' field was used as input ECX.
		if (entry->function == 0x00000007 && (entry->flags & KVM_CPUID_FLAG_SIGNIFCANT_INDEX) && entry->index == 0) {
			if (entry->ebx & (1U << 3)) has_bmi1 = true;         // EBX[3]  BMI1
			if (entry->ebx & (1U << 5)) has_avx2 = true;         // EBX[5]  AVX2
			if (entry->ebx & (1U << 8)) has_bmi2 = true;         // EBX[8]  BMI2
			if (entry->ebx & (1U << 16)) has_avx512f = true;     // EBX[16] AVX512F (Foundation)
			if (entry->ebx & (1U << 17)) has_avx512dq = true;    // EBX[17] AVX512DQ (Double/Quadword)
			if (entry->ebx & (1U << 28)) has_avx512cd = true;    // EBX[28] AVX512CD (Conflict Detection)
			if (entry->ebx & (1U << 30)) has_avx512bw = true;    // EBX[30] AVX512BW (Byte/Word)
			if (entry->ebx & (1U << 31)) has_avx512vl = true;    // EBX[31] AVX512VL (Vector Length Ext)
		}

		// Extended Features (Function 0x80000001)
		// Index is not typically varied for these flags.
		if (entry->function == 0x80000001 && !(entry->flags & KVM_CPUID_FLAG_SIGNIFCANT_INDEX)) {
			if (entry->ecx & (1U << 0)) has_lahf_sahf = true;    // ECX[0] LAHF/SAHF in 64-bit mode
			if (entry->ecx & (1U << 5)) has_lzcnt = true;        // ECX[5] LZCNT (ABM on AMD)
			if (entry->edx & (1U << 11)) has_syscall = true;     // EDX[11] SYSCALL/SYSRET
			// Note: CPUID.80000001h:EDX[20] is NX bit (No-Execute), not in the microarch levels list but important.
			// Note: CPUID.80000001h:EDX[29] is Long Mode (x86-64), fundamental.
		}
	}

	bool v1_supported = has_cmov && has_cx8 && has_fpu && has_fxsr && has_mmx && has_syscall && has_sse && has_sse2;
	bool v2_supported = v1_supported && has_cmpxchg16b && has_lahf_sahf && has_popcnt && has_sse3 && has_sse4_1 && has_sse4_2 && has_ssse3;
	bool v3_supported = v2_supported && has_avx && has_avx2 && has_bmi1 && has_bmi2 && has_f16c && has_fma && has_lzcnt && has_movbe && has_xsave;
	bool v4_supported = v3_supported && has_avx512f && has_avx512bw && has_avx512cd && has_avx512dq && has_avx512vl;

#if DEBUG
	printf("Checking x86-64 microarchitecture levels:\n");
	printf("  x86-64-v1 (baseline) supported: %s\n", v1_supported ? "Yes" : "No");
	printf("  x86-64-v2 supported: %s\n", v2_supported ? "Yes" : "No");
	printf("  x86-64-v3 supported: %s\n", v3_supported ? "Yes" : "No");
	printf("  x86-64-v4 supported: %s\n", v4_supported ? "Yes" : "No");
#endif	

	if (v4_supported) {return x86_64_v4;}
	if (v3_supported) {return x86_64_v3;}
	if (v2_supported) {return x86_64_v2;}
	if (v1_supported) {return x86_64_v1;}

	return x86_64_unknown;
}

void cpu_init_cpuid(struct vm *vm)
{
	free(vm->vcpu_cpuid);
	int max_entries = 100;

	vm->vcpu_cpuid = calloc(1, sizeof(*vm->vcpu_cpuid) + (max_entries * sizeof(*vm->vcpu_cpuid->entries)));
	vm->vcpu_cpuid->nent = max_entries;

	if (ioctl(vm->kvmfd, KVM_GET_SUPPORTED_CPUID, vm->vcpu_cpuid) < 0) {
		PANIC_PERROR("KVM_GET_SUPPORTED_CPUID");
	}

	/*
	x2APIC (CPUID leaf 1, ecx[21) and TSC deadline timer (CPUID leaf 1, ecx
	[24]) may be returned as true, but they depend on KVM_CREATE_IRQCHIP for
	in-kernel emulation of the local APIC.
	=> disable those bits
	*/
	for (uint32_t i = 0; i < vm->vcpu_cpuid->nent; i++) {
		/*
    	function:
    	    the eax value used to obtain the entry
    	index:
    	    the ecx value used to obtain the entry (for entries that are affected by ecx)
    	flags:
    	    an OR of zero or more of the following:
			KVM_CPUID_FLAG_SIGNIFCANT_INDEX: if the index field is valid
    	    eax, ebx, ecx, edx:
    	        the values returned by the cpuid instruction for this function/index combination
		*/
		struct kvm_cpuid_entry2 *entry = &vm->vcpu_cpuid->entries[i];
		if (entry->function == 1 && entry->index == 0) {
			// clearing x2APIC bit
			entry->ecx &= ~(1 << 21);
			// clearing TSC bit
			entry->ecx &= ~(1 << 24);
			break;
		}
	}

	if (ioctl(vm->vcpufd, KVM_SET_CPUID2, vm->vcpu_cpuid) < 0) {
		PANIC_PERROR("KVM_SET_CPUID2");
	}
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
	fpu->fcw = 0x37f;
	fpu->ftwx = 0xFF;    // all empty
	fpu->mxcsr = 0x1f80; //[ IM DM ZM OM UM PM ]; from qemu user
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

void cpu_init_v1(struct kvm_sregs2 *sregs, struct kvm_fpu *fpu) {
	cpu_init_fpu(fpu);
	cpu_init_sse(sregs);
}

void cpu_init_v2(void) {
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

void vm_init(struct vm *vm)
{
	cpu_init_cpuid(vm);

	microarchitecture_level vcpulevel = cpu_microarchitecture_levels(vm->vcpu_cpuid);

	struct kvm_regs regs;
	struct kvm_sregs2 sregs;
	struct kvm_fpu fpu;
	struct kvm_xcrs xcrs;

	if (ioctl(vm->vcpufd, KVM_GET_REGS, &regs) < 0) {
		PANIC_PERROR("KVM_GET_REGS");
	}
	if (ioctl(vm->vcpufd, KVM_GET_SREGS2, &sregs) < 0) {
		PANIC_PERROR("KVM_GET_SREGS2");
	}
	if (ioctl(vm->vcpufd, KVM_GET_FPU, &fpu) < 0) {
		PANIC_PERROR("KVM_GET_FPU");
	}
	if (ioctl(vm->vcpufd, KVM_GET_XCRS, &xcrs) < 0) {
		PANIC_PERROR("KVM_GET_XCRS");
	}

	cpu_init_long(&sregs, vm->memory);

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

	if (ioctl(vm->vcpufd, KVM_SET_REGS, &regs) < 0) {
		PANIC_PERROR("KVM_SET_REGS");
	}
	if (ioctl(vm->vcpufd, KVM_SET_SREGS2, &sregs) < 0) {
		PANIC_PERROR("KVM_SET_SREGS2");
	}
	if (ioctl(vm->vcpufd, KVM_SET_FPU, &fpu) < 0) {
		PANIC_PERROR("KVM_SET_FPU");
	}
	if (ioctl(vm->vcpufd, KVM_SET_XCRS, &xcrs) < 0) {
		PANIC_PERROR("KVM_SET_XCRS");
	}
}

void vm_set_debug(struct vm *vm, bool enable_debug)
{
	if (enable_debug) {
		vm->guest_debug.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW_BP |
					  KVM_GUESTDBG_USE_SW_BP;
	} else {
		vm->guest_debug.control = 0x0;
	}

	if (ioctl(vm->vcpufd, KVM_SET_GUEST_DEBUG, &vm->guest_debug) < 0) {
		PANIC_PERROR("KVM_SET_GUEST_DEBUG");
	}
	vm->debug_enabled = enable_debug;
}

void vm_set_debug_step(struct vm *vm, bool enable_step)
{
	if (!vm->debug_enabled) {
		PANIC("cannot step if debug is disabled");
	}

	if (enable_step) {
		vm->guest_debug.control |= KVM_GUESTDBG_SINGLESTEP;
	} else {
		vm->guest_debug.control &= ~(KVM_GUESTDBG_SINGLESTEP);
	}

	if (ioctl(vm->vcpufd, KVM_SET_GUEST_DEBUG, &vm->guest_debug) < 0) {
		PANIC_PERROR("KVM_SET_GUEST_DEBUG");
	}
}

void clear_regs(struct kvm_regs *regs)
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
}

void vm_load_program(struct vm *vm, char **argv)
{
	create_linux_view(argv, &vm->linux_view);

	// update vcpu
	struct kvm_regs regs;
	if (ioctl(vm->vcpufd, KVM_GET_REGS, &regs) < 0) {
		PANIC_PERROR("KVM_GET_REGS");
	}

	clear_regs(&regs); // clear some leftover junk ??

	struct user_regs_struct linux_view_regs;
	linux_view_get_regs(&vm->linux_view, &linux_view_regs);

	regs.rip = linux_view_regs.rip;
	regs.rsp = linux_view_regs.rsp;
	regs.rflags = 0x202; // linux sets up like this

	if (ioctl(vm->vcpufd, KVM_SET_REGS, &regs) < 0) {
		PANIC_PERROR("KVM_SET_REGS");
	}
}

int vm_run(struct vm *vm)
{
	vm_run_enable_sync_regs(vm);
	if (ioctl(vm->vcpufd, KVM_RUN, NULL) < 0) {
		PANIC_PERROR("KVM_RUN");
	}

	return vm->run->exit_reason;
}

bool is_syscall(struct vm *vm, struct kvm_regs *regs)
{
	uint8_t *inst = nullptr;

	if (vm_guest_to_host(vm, regs->rip, (void **)&inst, false) != 0) {
		return false;
	}

	uint16_t rip_content = inst[1] | (inst[0] << 8);

	return (bool)(rip_content == (uint16_t)SYSCALL_OPCODE);
}

void vm_page_fault_handler(struct vm *vm, uint64_t cr2)
{
	uint64_t missing_page_addr = TRUNC_PG(cr2);
	uintptr_t guest_vaddr = map_page(missing_page_addr);

	if (linux_view_read_mem(&vm->linux_view, (off64_t)missing_page_addr, (void *)guest_vaddr,
				PAGE_SIZE) != 0) {
		PANIC("linux_view_read_mem");
	}
}

void vm_exit_handler(int exit_code, struct vm *vm)
{
	switch (exit_code) {
	case KVM_EXIT_DEBUG:
		printf("KVM_EXIT_DEBUG\n");
		printf("exception: 0x%x\n"
		       "pad: 0x%x\n"
		       "pc: 0x%llx\n"
		       "dr6: 0x%llx\n"
		       "dr7: 0x%llx\n",
		       vm->run->debug.arch.exception, vm->run->debug.arch.pad,
		       vm->run->debug.arch.pc, vm->run->debug.arch.dr6, vm->run->debug.arch.dr7);
		break;
	case KVM_EXIT_HLT:
		printf("KVM_EXIT_HLT\n");
		break;

	case KVM_EXIT_SHUTDOWN:
		struct kvm_regs *regs = vm_get_regs(vm);
		struct kvm_sregs *sregs = vm_get_sregs(vm);

		// page fault
		if (sregs->cr2 != 0) {
#if DEBUG
			printf("page fault addr: %p, inst: %p\n", (void *)sregs->cr2,
			       (void *)regs->rip);
#endif
			vm_page_fault_handler(vm, sregs->cr2);

			sregs->cr2 = 0;
			vm_set_sregs(vm);
		} else if (is_syscall(vm, regs)) {
			if (syscall_handler(vm, regs) == ENOSYS) {
				vcpu_events_logs(vm);
				vcpu_regs_log(vm);
				exit(-1);
			}

			// skip syscall instruction
			regs->rip += SYSCALL_OP_SIZE;
			vm_set_regs(vm);
		} else {
			printf("unespected shutdown\n");
			vcpu_events_logs(vm);
			vcpu_regs_log(vm);
			exit(-1);
		}
		break;
	case KVM_EXIT_FAIL_ENTRY:
		printf("KVM_EXIT_FAIL_ENTRY: 0x%lx\n",
		       (uint64_t)vm->run->fail_entry.hardware_entry_failure_reason);
		exit(-1);
		break;
	case KVM_EXIT_INTERNAL_ERROR:
		printf("KVM_EXIT_INTERNAL_ERROR: suberror = 0x%x\n", vm->run->internal.suberror);
		exit(-1);
		break;
	default:
		printf("Odd exit reason: %d\n", vm->run->exit_reason);
		exit(EXIT_FAILURE);
		break;
	}
}
