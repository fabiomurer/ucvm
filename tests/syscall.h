#include <unistd.h>

long syscall_syscall(long syscall_number, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6) {

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
    }
    
    return syscall_no;
}


