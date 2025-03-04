#include <asm/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <linux/kvm.h>
#include <stdlib.h>

#include "utils.h"
#include "vsyscall.h"

// https://www.sandpile.org/x86/except.htm
char exceptions_names[][30] = {
    "divide error", 
    "debug",
    "non-maskable interrupt",
    "breakpoint",
    "overflow",
    "boundary range exceeded",
    "undefined opcode",
    "device not available",
    "double fault",
    "reserved",
    "invalid TSS",
    "not present",
    "stack segment",
    "general protection",
    "page fault",
    "reserved",
    "math fault",
    "alignment checking",
    "machine check",
    "extended math fault",
    "virtualization exception",
    "control protection exception",
    "reserved",
    "reserved",
    "reserved",
    "reserved",
    "reserved",
    "reserved",
    "HV injection exception",
    "VMM comm. exception",
    "security exception",
    "reserved"
};

void vcpu_events_logs(struct vm* vm) {
    struct kvm_vcpu_events events;

    if (ioctl(vm->vcpufd, KVM_GET_VCPU_EVENTS, &events) < 0) {
        perror("KVM_GET_VCPU_EVENTS");
        exit(-1);
    }

    printf(
        "exceptions:\n\t"
        "injected: %d\n\t"
        "nr: %d [%s]\n\t"
        "has_error_code: %d\n\t"
        "pending: %d\n\t"
        "error_code: %d\n\t"
        "exception_has_payload: %d\n\t"
        "exception_payload: %p\n",
        events.exception.injected,
        events.exception.nr,
        exceptions_names[events.exception.nr],
        events.exception.has_error_code,
        events.exception.pending,
        events.exception.error_code,
        events.exception_has_payload,
        (void*)events.exception_payload
    );

    printf("sipi_vector: %d\n", events.sipi_vector);

    printf("flags: %X\n", events.flags);
    if (events.flags & KVM_VCPUEVENT_VALID_NMI_PENDING) {
        printf("\tKVM_VCPUEVENT_VALID_NMI_PENDING\n");
    }
    if (events.flags & KVM_VCPUEVENT_VALID_SIPI_VECTOR) {
        printf("\tKVM_VCPUEVENT_VALID_SIPI_VECTOR\n");
    }
    if (events.flags & KVM_VCPUEVENT_VALID_SHADOW) {
        printf("\tKVM_VCPUEVENT_VALID_SHADOW\n");
    }
    if (events.flags & KVM_VCPUEVENT_VALID_SMM) {
        printf("\tKVM_VCPUEVENT_VALID_SMM\n");
    }
    if (events.flags & KVM_VCPUEVENT_VALID_PAYLOAD) {
        printf("\tKVM_VCPUEVENT_VALID_PAYLOAD\n");
    }
    if (events.flags & KVM_VCPUEVENT_VALID_TRIPLE_FAULT) {
        printf("\tKVM_VCPUEVENT_VALID_TRIPLE_FAULT\n");
    }

    printf(
        "interrupt:\n\t"
        "injected: %d\n\t"
        "nr: %d\n\t"
        "soft: %d\n\t"
        "shadow: %d\n",
        events.interrupt.injected,
        events.interrupt.nr,
        events.interrupt.soft,
        events.interrupt.shadow
    );

    printf(
        "nmi:\n\t"
        "injected: %d\n\t"
        "pending: %d\n\t"
        "masked: %d\n\t"
        "pad: %d\n",
        events.nmi.injected,
        events.nmi.pending,
        events.nmi.masked,
        events.nmi.pad
    );

    printf(
        "smi:\n\t"
        "smm: %d\n\t"
        "pending: %d\n\t"
        "smm_inside_nmi: %d\n\t"
        "latched_init: %d\n",
        events.smi.smm,
        events.smi.pending,
        events.smi.smm_inside_nmi,
        events.smi.latched_init
    );

    printf(
        "triple fault:\n\t"
        "pending: %d\n", events.triple_fault.pending
    );
}

void vcpu_regs_log(struct vm* vm) {
    struct kvm_regs regs;
	if (ioctl(vm->vcpufd, KVM_GET_REGS, &regs) < 0) {
		panic("KVM_GET_REGS");
	}

    printf(
        "regs\n\t"
        "RIP: %p\n\t"
        "RSP: %p\n\t"
        "RFLAGS: 0x%llx\n",
        (void*)regs.rip,
        (void*)regs.rsp,
        regs.rflags
    );

    u_int8_t* exec_inst_ptr = (u_int8_t*)vm_guest_to_host(vm, regs.rip);
    printf("exec_instr: ");

    for (int i = 10; i >= 0; i--) {
        printf("%X ", exec_inst_ptr[i]);
    }

    printf("\n");
}