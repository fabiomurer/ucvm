#define _GNU_SOURCE
#include <asm/kvm.h>
#include <signal.h>
#include <sys/wait.h>
#include "utils.h"
#include "vm.h"
#include "vmm.h"
#include "load_linux.h"
#include "load_kvm.h"
#include "vsyscall.h"
#include "vminfo.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/kvm.h>
#include <stdbool.h>
#include <error.h>
#include <errno.h>
#include <sched.h>

#define KVM_DEVICE "/dev/kvm"

struct vm vm_create(void) {
    struct vm vm = {0};
    vm.debug_enabled = false;

    // connect to kvm
    if ((vm.kvmfd = open(KVM_DEVICE, O_RDWR | O_CLOEXEC)) < 0) {
        PANIC_PERROR("Failed to open " KVM_DEVICE);
    }

    // Check KVM API version
    int api_version = ioctl(vm.kvmfd, KVM_GET_API_VERSION, 0);
    if (api_version == -1) PANIC_PERROR("KVM_GET_API_VERSION");
    if (api_version != 12) { 
        PANIC("KVM API version not supported");
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

    if ((vm.run = mmap(NULL, vcpu_mmap_size, 
            PROT_READ | PROT_WRITE, 
            MAP_SHARED, 
            vm.vcpufd, 0)) == MAP_FAILED) {
        PANIC_PERROR("MMAP");
    }

    // pin the vcpu at one cop
    cpu_set_t set;
    CPU_ZERO(&set);
    // pin to cpu 0
    CPU_SET(0, &set);
    if (sched_setaffinity(getpid(), sizeof(set), &set) == -1) {
        PANIC_PERROR("sched_setaffinity");
    }

    // create memory
    if ((vm.memory = mmap(
                NULL, MEMORY_SIZE, 
                PROT_READ | PROT_WRITE, 
                MAP_SHARED | MAP_ANONYMOUS, 
                -1, 0)
            ) == MAP_FAILED) {
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

void cpu_init_cpuid(struct vm* vm) {
    struct kvm_cpuid2 *cpuid;
    int max_entries = 100;
    
    cpuid = calloc(1, sizeof(*cpuid) + max_entries * sizeof(*cpuid->entries));
    cpuid->nent = max_entries;

    if (ioctl(vm->kvmfd, KVM_GET_SUPPORTED_CPUID, cpuid) < 0) {
        PANIC_PERROR("KVM_GET_SUPPORTED_CPUID");
    }

    /*
    x2APIC (CPUID leaf 1, ecx[21) and TSC deadline timer (CPUID leaf 1, ecx
    [24]) may be returned as true, but they depend on KVM_CREATE_IRQCHIP for 
    in-kernel emulation of the local APIC. 
    => disable those bits
    */
    for (uint32_t i = 0; i < cpuid->nent; i++) {
        struct kvm_cpuid_entry2 *entry = &cpuid->entries[i];
        if (entry->function == 1 && entry->index == 0) {
            // clearing x2APIC bit
            entry->ecx &= ~(1 << 21);
            // clearing TSC bit
            entry->ecx &= ~(1 << 24);
            break;
        }
    }

    if (ioctl(vm->vcpufd, KVM_SET_CPUID2, cpuid) < 0) {
        PANIC_PERROR("KVM_SET_CPUID2");
    }
}

void cpu_init_extensions(struct kvm_sregs2* sregs) {
    #define CR4_OSXSAVE     (1ULL << 18)     
    #define CR4_FSGSBASE    (1ULL << 16)        
    #define CR4_OSFXSR      (1ULL << 9)
    
    // sse
    /*
	clear the CR0.EM bit (bit 2) [ CR0 &= ~(1 << 2) ]
	set the CR0.MP bit (bit 1) [ CR0 |= (1 << 1) ]
	set the CR4.OSFXSR bit (bit 9) [ CR4 |= (1 << 9) ]
	set the CR4.OSXMMEXCPT bit (bit 10) [ CR4 |= (1 << 10) ]
	*/
	sregs->cr0 &= ~(1ULL << 2); // CR0_EM
	sregs->cr0 &= ~(1ULL << 3); // CR0_TS
	sregs->cr0 |=  (1ULL << 1);
	sregs->cr4 |=  CR4_OSFXSR;
	sregs->cr4 |=  (1ULL << 10);

    // avx
    // Both SSE and OSXSAVE must be enabled before allowing. Failing to do so will also produce an #UD. 
    sregs->cr4 |= CR4_OSXSAVE | CR4_FSGSBASE;
}

void cpu_init_fpu(struct kvm_fpu* fpu) {
    /*
    FNINIT will reset the user-visible part of the FPU stack. This will set precision to 64-bit 
    and rounding to nearest, which should be correct for most operations. It will also
    mask all exceptions from causing an interrupt.
    */
    fpu->fcw = 0x37f;
	fpu->ftwx = 0xFF; // all empty
	fpu->mxcsr = 0x1f80; //[ IM DM ZM OM UM PM ]; from qemu user
}

void cpu_init_xcrs(struct kvm_xcrs* xrcs) {
    #define XCR0_X87    (1ULL << 0)  // x87 FPU/MMX state (must be 1)
    #define XCR0_SSE    (1ULL << 1)  // SSE state
    #define XCR0_AVX    (1ULL << 2)  // AVX state

    #define XCR0_OPMASK (1LL << 5)
    #define ZMM_Hi256   (1LL << 6)
    #define Hi16_ZMM    (1LL << 7)

    for (uint32_t i = 0; i < xrcs->nr_xcrs; i++) {
        // found xcr0
        if (xrcs->xcrs[i].xcr == 0) {
            // avx
            xrcs->xcrs[i].value |= XCR0_X87 | XCR0_SSE | XCR0_AVX;
            // avx512 not supported
            // xrcs->xcrs[i].value |= XCR0_OPMASK | ZMM_Hi256 | Hi16_ZMM;
            break;
        }
    }
}

void cpu_init_cache(struct kvm_sregs2* sregs) {
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

void vm_init(struct vm* vm) {
    cpu_init_cpuid(vm);

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

    cpu_init_extensions(&sregs);

    cpu_init_fpu(&fpu);

    cpu_init_xcrs(&xcrs);
    
    cpu_init_cache(&sregs);
    
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

void vm_set_debug(struct vm* vm, bool enable_debug) {

    if (enable_debug) {
        vm->guest_debug.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW_BP | KVM_GUESTDBG_USE_SW_BP;
    } else {
        vm->guest_debug.control = 0x0;
    }

    if (ioctl(vm->vcpufd, KVM_SET_GUEST_DEBUG, &vm->guest_debug) < 0) {
		PANIC_PERROR("KVM_SET_GUEST_DEBUG");
	}
    vm->debug_enabled = enable_debug;
}

void vm_set_debug_step(struct vm* vm, bool enable_step) {
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

void vm_load_program(struct vm* vm, struct linux_proc* linux_proc) {
    load_linux(linux_proc->argv, linux_proc);

    // update vcpu
    struct kvm_regs regs;
    if (ioctl(vm->vcpufd, KVM_GET_REGS, &regs) < 0) {
        PANIC_PERROR("KVM_GET_REGS");
    }

    regs.rip = linux_proc->rip;
    regs.rsp = linux_proc->rsp;

    if (ioctl(vm->vcpufd, KVM_SET_REGS, &regs) < 0) {
        PANIC_PERROR("KVM_SET_REGS");
    }

    load_kvm(linux_proc->pid);

    // kill traced process
    if (kill(linux_proc->pid, SIGKILL) == -1) {
        perror("kill");
        exit(EXIT_FAILURE);
    }
    
    int status;
    waitpid(linux_proc->pid, &status, 0);
}

int vm_run(struct vm* vm) {
    
    if (ioctl(vm->vcpufd, KVM_RUN, NULL) < 0) {
        PANIC_PERROR("KVM_RUN");
    }

    return vm->run->exit_reason;
}

void vm_exit_handler(int exit_code, struct vm* vm, struct linux_proc* linux_proc) {
    
	switch (exit_code) {
    case KVM_EXIT_DEBUG:
        printf("KVM_EXIT_DEBUG\n");
        printf(
            "exception: 0x%x\n"
            "pad: 0x%x\n"
            "pc: 0x%llx\n"
            "dr6: 0x%llx\n"
            "dr7: 0x%llx\n", 
            vm->run->debug.arch.exception,
            vm->run->debug.arch.pad,
            vm->run->debug.arch.pc,
            vm->run->debug.arch.dr6,
            vm->run->debug.arch.dr7
        );
        break;
	case KVM_EXIT_HLT:
		printf("KVM_EXIT_HLT\n");
		break;
		
	case KVM_EXIT_SHUTDOWN:
		struct kvm_regs regs;
		if (ioctl(vm->vcpufd, KVM_GET_REGS, &regs) < 0) {
			PANIC_PERROR("KVM_GET_REGS");
		}
		if (is_syscall(vm, &regs)) {
			
			if (syscall_handler(vm, linux_proc, &regs) == ENOSYS) {
                vcpu_events_logs(vm);
			    vcpu_regs_log(vm);
				printf("syscall num: %lld not supported\n", regs.rax);
				exit(-1);
			}
			
            // skip syscall instruction
			regs.rip += SYSCALL_OP_SIZE;
			if (ioctl(vm->vcpufd, KVM_SET_REGS, &regs) < 0) {
				PANIC_PERROR("KVM_SET_REGS");
			}
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
		break;
	case KVM_EXIT_INTERNAL_ERROR:
		printf("KVM_EXIT_INTERNAL_ERROR: suberror = 0x%x\n",
		     vm->run->internal.suberror);
        break;
	default:
		printf("Odd exit reason: %d\n", vm->run->exit_reason);
        exit(EXIT_FAILURE);
		break;
	}
}
