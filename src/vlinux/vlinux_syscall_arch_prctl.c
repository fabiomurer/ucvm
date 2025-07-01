#include "vlinux/vlinux_syscall_arch_prctl.h"
#include "utils.h"
#include <asm/prctl.h>
#include <stdio.h>

uint64_t vlinux_syscall_arch_prctl(struct vm *vm, uint64_t op, uint64_t addr)
{
	uint64_t ret = -1;

	switch (op) {
	case ARCH_SET_FS:
		struct kvm_sregs *sregs = vm_get_sregs(vm);

		// set the base address of fs register to addr
		sregs->fs.base = addr;

		vm_set_sregs(vm);
		return 0;
	default:
		PANIC("vlinux_syscall_arch_prctl OP NOT SUPPORTED");
		break;
	}
	return ret;
}
