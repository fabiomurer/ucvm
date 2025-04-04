
#include <stddef.h>
#include <stdint.h>
static inline long my_syscall(long syscall_number, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6) {

    register long syscall_no __asm__("rax") = syscall_number;
    register long a1 __asm__("rdi") = arg1;
    register long a2 __asm__("rsi") = arg2;
    register long a3 __asm__("rdx") = arg3;
    register long a4 __asm__("r10") = arg4;
    register long a5 __asm__("r8") = arg5;
    register long a6 __asm__("r9") = arg6;
    __asm__("syscall");

    if (syscall_no < 0) {
        return -syscall_no;
    } else {
        return syscall_no;
    }
}


void __attribute__((noreturn)) __attribute__((section(".start"))) _start(void) {
    size_t x = 0;
    for (size_t i = 0; i < 100000; i++) {
        for (size_t j = 0; j < 10000; j++) {
            x = i - j;
        }
    }

    my_syscall(60, x, 0, 0, 0, 0, 0); // exit succes
    for (;;) __asm__("hlt");
}
