#include "vlinux/syscall_set_tid_address.h"

uint64_t syscall_set_tid_address(void)
{
	/*
	    The system call set_tid_address() sets the clear_child_tid value
	    for the calling thread to tidptr.

	    set_tid_address() always returns the caller's thread ID.
	    for now 1 thread -> thread ID = 0
	    */

	return 0;
}
