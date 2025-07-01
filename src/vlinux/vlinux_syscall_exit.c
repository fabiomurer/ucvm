#include "vlinux/vlinux_syscall_exit.h"
#include <unistd.h>

uint64_t vlinux_syscall_exit(int status)
{
    _exit(status);
}
