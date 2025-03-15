
#include <stddef.h>
#include <stdint.h>
static inline long my_syscall(long syscall_number, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6) {

    register long syscall_no __asm__("rax") = syscall_number;
    register long a1 __asm__("rdi") = arg1;
    register long a2 __asm__("rsi") = arg2;
    register long a3 __asm__("rdx") = arg3;
    register long a4 __asm__("r10") = arg4;
    register long a5 __asm__("r8") = arg5;
    register long a6 __asm__("r8") = arg6;
    __asm__("syscall");

    if (syscall_no < 0) {
        return -syscall_no;
    } else {
        return syscall_no;
    }
}

#define SIZE 1000UL

void multiply_matrices(double a[SIZE][SIZE], double b[SIZE][SIZE], double c[SIZE][SIZE]) {
    for (uint64_t i = 0; i < SIZE; i++) {
        for (uint64_t j = 0; j < SIZE; j++) {
            c[i][j] = 0;
            for (uint64_t k = 0; k < SIZE; k++) {
                c[i][j] += a[i][k] * b[k][j];
            }
        }
    }
}

static double a[SIZE][SIZE], b[SIZE][SIZE], c[SIZE][SIZE];

void __attribute__((noreturn)) __attribute__((section(".start"))) _start(void) {

    // Initialize matrices with a simple pattern
    for (uint64_t i = 0; i < SIZE; i++) {
        for (uint64_t j = 0; j < SIZE; j++) {
            a[i][j] = i + j;
            b[i][j] = i - j;
        }
    }

    multiply_matrices(a, b, c);

    my_syscall(60, 0, 0, 0, 0, 0, 0); // exit succes
    for (;;) __asm__("hlt");
}
