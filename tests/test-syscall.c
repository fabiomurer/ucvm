#include "syscall.h"
#include <asm/unistd_64.h>
#include <stddef.h>

#define ITERATIONS 100000

void __attribute__((noreturn)) __attribute__((section(".start"))) _start(void) {

    for (size_t i = 0; i < ITERATIONS; i++) {
        syscall_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0);
    }

    syscall_syscall(__NR_exit_group, 0, 0, 0, 0, 0, 0); // exit succes
    for (;;) { 
        __asm__("hlt");
    }
}
