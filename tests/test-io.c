#include <stddef.h>

// System call numbers for x86_64 Linux
#define SYS_READ 0
#define SYS_WRITE 1
#define SYS_OPEN 2
#define SYS_CLOSE 3
#define SYS_EXIT 60

// File open flags
#define O_RDONLY 0
#define O_WRONLY 1
#define O_CREAT 64
#define O_TRUNC 512

// File permissions (0644 = owner rw, group/others r)
#define FILE_MODE 0644

// Buffer size (8KB)
#define BUFFER_SIZE (8 * 1024)

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
    // Buffer to store data from urandom
    char buffer[BUFFER_SIZE];
    
    // Open /dev/urandom
    const char urandom_path[] = "/dev/urandom";
    long urandom_fd = my_syscall(SYS_OPEN, (long)urandom_path, O_RDONLY, 0, 0, 0, 0);
    
    // Check if open failed
    if (urandom_fd < 0) {
        my_syscall(SYS_EXIT, 1, 0, 0, 0, 0, 0); // Exit with error
    }
    
    // Open /tmp/trash file for writing (create if doesn't exist, truncate if it does)
    const char trash_path[] = "/tmp/trash";
    long trash_fd = my_syscall(SYS_OPEN, (long)trash_path, O_WRONLY | O_CREAT | O_TRUNC, FILE_MODE, 0, 0, 0);
    
    // Check if open failed
    if (trash_fd < 0) {
        my_syscall(SYS_CLOSE, urandom_fd, 0, 0, 0, 0, 0);
        my_syscall(SYS_EXIT, 2, 0, 0, 0, 0, 0); // Exit with error
    }
    
    // Read from urandom and write to /tmp/trash 1000 times
    for (size_t i = 0; i < 10000; i++) {
        // Read 8KB from urandom
        long bytes_read = my_syscall(SYS_READ, urandom_fd, (long)buffer, BUFFER_SIZE, 0, 0, 0);
        
        // Check if read failed
        if (bytes_read <= 0) {
            my_syscall(SYS_CLOSE, urandom_fd, 0, 0, 0, 0, 0);
            my_syscall(SYS_CLOSE, trash_fd, 0, 0, 0, 0, 0);
            my_syscall(SYS_EXIT, 3, 0, 0, 0, 0, 0); // Exit with error
        }
        
        // Write to /tmp/trash
        long bytes_written = my_syscall(SYS_WRITE, trash_fd, (long)buffer, bytes_read, 0, 0, 0);
        
        // Check if write failed
        if (bytes_written != bytes_read) {
            my_syscall(SYS_CLOSE, urandom_fd, 0, 0, 0, 0, 0);
            my_syscall(SYS_CLOSE, trash_fd, 0, 0, 0, 0, 0);
            my_syscall(SYS_EXIT, 4, 0, 0, 0, 0, 0); // Exit with error
        }
    }
    
    // Close files
    my_syscall(SYS_CLOSE, urandom_fd, 0, 0, 0, 0, 0);
    my_syscall(SYS_CLOSE, trash_fd, 0, 0, 0, 0, 0);
    
    // Exit successfully
    my_syscall(SYS_EXIT, 0, 0, 0, 0, 0, 0);
    
    // This should never be reached, but included for completeness
    for (;;) __asm__("hlt");
}