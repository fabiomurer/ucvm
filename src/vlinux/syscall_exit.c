#include "vlinux/syscall_exit.h"
#include <unistd.h>

uint64_t syscall_exit(int status)
{
    _exit(status);
}
