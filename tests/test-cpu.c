#include "syscall.h"
#include <asm/unistd_64.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/cdefs.h>

#define ITERATIONS 50000

void __attribute__((noreturn)) __attribute__((section(".start"))) _start(void) {
    long x = 0;
    for (long i = 0; i < ITERATIONS; i++) {
        for (long j = 0; j < ITERATIONS; j++) {
            x = i - j;
        }
    }

    syscall_syscall(__NR_exit_group, x, 0, 0, 0, 0, 0);
    for (;;){
        __asm__("hlt");
    }
}
