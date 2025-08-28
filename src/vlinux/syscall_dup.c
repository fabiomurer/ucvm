#include "vlinux/syscall_dup.h"
#include <unistd.h>

int syscall_dup(int oldfd)
{
    return dup(oldfd);
}
