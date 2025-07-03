#include "vlinux/syscall_getpid.h"
#include <unistd.h>

uint64_t syscall_getpid(void) {
    // TODO: give its own pid and not the ucv pid
    return getpid();
}
