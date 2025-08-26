#include "cpu.h"
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
	vm->run->kvm_valid_regs = KVM_SYNC_X86_REGS | KVM_SYNC_X86_SREGS | KVM_SYNC_X86_EVENTS;
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

struct kvm_vcpu_events *vm_get_vcpu_events(struct vm *vm)
{
	if ((vm->run->kvm_valid_regs & KVM_SYNC_X86_EVENTS) == 0) {
		PANIC("EVENTS not valid");
	}

	return &vm->run->s.regs.events;
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

	int support_exception_payload =
		ioctl(vm.kvmfd, KVM_CHECK_EXTENSION, KVM_CAP_EXCEPTION_PAYLOAD);
	if (support_exception_payload <= 0) {
		PANIC("KVM_CAP_EXCEPTION_PAYLOAD not supported");
	}

	int supported_sync_regs = ioctl(vm.kvmfd, KVM_CHECK_EXTENSION, KVM_CAP_SYNC_REGS);
	if (supported_sync_regs != KVM_SYNC_X86_VALID_FIELDS) {
		PANIC("KVM_CAP_SYNC_REGS not supported");
	}

	// create a vm
	if ((vm.vmfd = ioctl(vm.kvmfd, KVM_CREATE_VM, 0)) < 0) {
		PANIC_PERROR("KVM_CREATE_VM");
	}

	struct kvm_enable_cap exception_payload_enabled = {
		.cap = KVM_CAP_EXCEPTION_PAYLOAD,
		.args[0] = 1,
	};
	if (ioctl(vm.vmfd, KVM_ENABLE_CAP, &exception_payload_enabled) < 0) {
		PANIC("KVM_CAP_EXCEPTION_PAYLOAD");
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
	if ((vm.vmm.mem_host_virtual_addr = mmap(NULL, MEMORY_SIZE, PROT_READ | PROT_WRITE,
						 MAP_SHARED | MAP_ANONYMOUS, -1, 0)) ==
	    MAP_FAILED) {
		PANIC_PERROR("MMAP");
	}
	memset(vm.vmm.mem_host_virtual_addr, 0, MEMORY_SIZE); // ?
	struct kvm_userspace_memory_region region = {
		.slot = MEMORY_SLOT,
		.flags = 0,
		.guest_phys_addr = GUEST_PHYS_ADDR,
		.memory_size = MEMORY_SIZE,
		.userspace_addr = (uint64_t)vm.vmm.mem_host_virtual_addr,
	};

	if (ioctl(vm.vmfd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
		PANIC_PERROR("KVM_SET_USER_MEMORY_REGION");
	}

	return vm;
}

void vm_init(struct vm *vm)
{
	cpu_init(vm);
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
	uintptr_t guest_vaddr = vmm_map_page(&vm->vmm, missing_page_addr);

	if (linux_view_read_mem(&vm->linux_view, (off64_t)missing_page_addr, (void *)guest_vaddr,
				PAGE_SIZE) != 0) {
		PANIC("linux_view_read_mem");
	}
}

#define EXCEPTION_UD 0x6
#define EXCEPTION_PF 0xE

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
		struct kvm_vcpu_events *events = vm_get_vcpu_events(vm);

		switch (events->exception.nr) {
		case EXCEPTION_UD:
			if (is_syscall(vm, regs)) {
				if (syscall_handler(vm, regs) == ENOSYS) {
					vcpu_logs_exit(vm, EXIT_FAILURE);
				}

				// skip syscall instruction
				regs->rip += SYSCALL_OP_SIZE;
				vm_set_regs(vm);
			} else {
				printf("undefined opcode");
				vcpu_logs_exit(vm, EXIT_FAILURE);
			}
			break;

		case EXCEPTION_PF:
#if DEBUG
			printf("page fault addr: %p, inst: %p\n", (void *)sregs->cr2,
			       (void *)regs->rip);
#endif
			vm_page_fault_handler(vm, sregs->cr2);

			sregs->cr2 = 0;
			vm_set_sregs(vm);

			break;

		default:
			printf("unespected shutdown\n");
			vcpu_logs_exit(vm, EXIT_FAILURE);
			break;
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
