#include "syscall.h"
#include <asm/unistd_64.h>
#include <stddef.h>

/**
 * @brief A simple `strlen` implementation to avoid any library dependencies.
 */
static size_t get_strlen(const char* str) {
    const char* s = str;
    while (*s) {
        s++;
    }
    return s - str;
}

/**
 * @brief The entry point of the program. Marked as noreturn and placed in the .start section.
 */
void __attribute__((noreturn)) __attribute__((section(".start"))) _start(void) {
    unsigned short cs_val;

    // Use inline assembly to move the value from the CS register into our variable.
    // "mov %cs, %ax" is the instruction, and we use "=a"(cs_val) to capture
    // the value from the RAX/EAX/AX register.
    __asm__ volatile ("mov %%cs, %0" : "=a"(cs_val));

    // The Current Privilege Level (CPL) is stored in the lower 2 bits of CS.
    // We use a bitwise AND to isolate them.
    const unsigned short cpl = cs_val & 0x3;

    const char *msg;

    // Check the CPL to determine the mode.
    if (cpl == 0) {
        msg = "Running in Kernel Mode (Ring 0)\n";
    } else if (cpl == 3) {
        msg = "Running in User Mode (Ring 3)\n";
    } else {
        // This case is rare in modern OSes but possible.
        msg = "Running in an intermediate mode (Ring 1 or 2)\n";
    }

    // Write the result to stdout (file descriptor 1).
    syscall_syscall(__NR_write, 1, (long)msg, get_strlen(msg), 0, 0, 0);

    // Exit the process group with a success code.
    syscall_syscall(__NR_exit_group, 0, 0, 0, 0, 0, 0);

    // This part should be unreachable, but it's good practice to have a halt
    // loop in case the exit syscall somehow fails.
    for (;;) {
        __asm__ volatile ("hlt");
    }
}
