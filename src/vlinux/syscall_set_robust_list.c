#include "vlinux/syscall_set_robust_list.h"
#include <linux/futex.h>

uint64_t syscall_set_robust_list(uint64_t head, size_t size)
{
	/*
	    The set_robust_list() system call requests the kernel to record
	    the head of the list of robust futexes owned by the calling
	    thread.  The head argument is the list head to record.  The size
	    argument should be sizeof(*head).
	    */

	if (size == sizeof(struct robust_list_head) && head != 0) {
		// linux_proc->robust_list_head_ptr = arg1;
		return 0;
	}

	return -1;
}
