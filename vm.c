#include <asm/kvm.h>
#define _GNU_SOURCE

#include "utils.h"
#include "vm.h"
#include "vmm.h"

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

#define KVM_DEVICE "/dev/kvm"

struct vm vm_create(void) {
    struct vm vm;

    // connect to kvm
    if ((vm.kvmfd = open(KVM_DEVICE, O_RDWR | O_CLOEXEC)) < 0) {
        panic("Failed to open " KVM_DEVICE);
    }

    // Check KVM API version
    int api_version = ioctl(vm.kvmfd, KVM_GET_API_VERSION, 0);
    if (api_version == -1) panic("KVM_GET_API_VERSION");
    if (api_version != 12) { 
        panic("KVM API version not supported");
    }

    // create a vm
    if ((vm.vmfd = ioctl(vm.kvmfd, KVM_CREATE_VM, 0)) < 0) {
        panic("KVM_CREATE_VM");
    }

    // create vcpu
    ssize_t vcpu_mmap_size;
    if ((vcpu_mmap_size = ioctl(vm.kvmfd, KVM_GET_VCPU_MMAP_SIZE, 0)) <= 0) {
        panic("KVM_GET_VCPU_MMAP_SIZE");
    }

    if ((vm.vcpufd = ioctl(vm.vmfd, KVM_CREATE_VCPU, 0)) < 0) {
        panic("KVM_CREATE_VCPU");
    }

    if ((vm.run = mmap(NULL, vcpu_mmap_size, 
            PROT_READ | PROT_WRITE, 
            MAP_SHARED, 
            vm.vcpufd, 0)) == MAP_FAILED) {
        panic("MMAP");
    }

    // create memory
    if ((vm.memory = mmap(
                NULL, MEMORY_SIZE, 
                PROT_READ | PROT_WRITE, 
                MAP_SHARED | MAP_ANONYMOUS, 
                -1, 0)
            ) == MAP_FAILED) {
        panic("MMAP");
    }

    struct kvm_userspace_memory_region region = {
        .slot = MEMORY_SLOT,
        .flags = 0,
        .guest_phys_addr = GUEST_PHYS_ADDR,
        .memory_size = MEMORY_SIZE,
        .userspace_addr = (uint64_t)vm.memory,
    };

    if (ioctl(vm.vmfd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
        panic("KVM_SET_USER_MEMORY_REGION");
    }

    return vm;
}

void cpu_init_cpuid(struct vm* vm) {
    struct kvm_cpuid2 *cpuid;
    int max_entries = 100;
    
    cpuid = calloc(1, sizeof(*cpuid) + max_entries * sizeof(*cpuid->entries));
    cpuid->nent = max_entries;

    if (ioctl(vm->kvmfd, KVM_GET_SUPPORTED_CPUID, cpuid) < 0) {
        panic("KVM_GET_SUPPORTED_CPUID");
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
        panic("KVM_SET_CPUID2");
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

void vm_init(struct vm* vm) {
    cpu_init_cpuid(vm);

    struct kvm_regs regs;
    struct kvm_sregs2 sregs;
    struct kvm_fpu fpu;
    struct kvm_xcrs xcrs;

    if (ioctl(vm->vcpufd, KVM_GET_REGS, &regs) < 0) {
        panic("KVM_GET_REGS");
    }
    if (ioctl(vm->vcpufd, KVM_GET_SREGS2, &sregs) < 0) {
        panic("KVM_GET_SREGS2");
    }
    if (ioctl(vm->vcpufd, KVM_GET_FPU, &fpu) < 0) {
        panic("KVM_GET_FPU");
    }
    if (ioctl(vm->vcpufd, KVM_GET_XCRS, &xcrs) < 0) {
        panic("KVM_GET_XCRS");
    }

    cpu_init_long(&sregs, vm->memory);

    cpu_init_extensions(&sregs);

    cpu_init_fpu(&fpu);

    cpu_init_xcrs(&xcrs);
    
    if (ioctl(vm->vcpufd, KVM_SET_REGS, &regs) < 0) {
        panic("KVM_SET_REGS");
    }
    if (ioctl(vm->vcpufd, KVM_SET_SREGS2, &sregs) < 0) {
        panic("KVM_SET_SREGS2");
    }
    if (ioctl(vm->vcpufd, KVM_SET_FPU, &fpu) < 0) {
        panic("KVM_SET_FPU");
    }
    if (ioctl(vm->vcpufd, KVM_SET_XCRS, &xcrs) < 0) {
        panic("KVM_SET_XCRS");
    }
}
