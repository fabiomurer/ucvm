#include "utils.h"
#include "vlinux/syscall_prlimit64.h"
#include <stdio.h>
#include <sys/resource.h>

// TODO: add all arguments
uint64_t syscall_prlimit64(pid_t pid, int resource)
{
	if (pid == 0 && resource == RLIMIT_STACK) {
		// for vm no limit for stack-> do nothing ignore
		return 0;
	}

	PANIC("__NR_prlimit64 case not supported");
}
