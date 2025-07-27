#include <asm/unistd_64.h>
#include <fcntl.h>
#include <stddef.h>
#include "syscall.h"

#define ITERATIONS 10000

// File permissions (0644 = owner rw, group/others r)
#define FILE_MODE 0644

// Buffer size (8KB)
#define BUFFER_SIZE (8 * 1024)


void __attribute__((noreturn)) __attribute__((section(".start"))) _start(void) {
    // Buffer to store data from urandom
    char buffer[BUFFER_SIZE];
    
    // Open /dev/urandom
    const char urandom_path[] = "/dev/urandom";
    long urandom_fd = syscall_syscall(__NR_open, (long)urandom_path, O_RDONLY, 0, 0, 0, 0);
    
    // Check if open failed
    if (urandom_fd < 0) {
        syscall_syscall(__NR_exit_group, 1, 0, 0, 0, 0, 0); // Exit with error
    }
    
    // Open /tmp/trash file for writing (create if doesn't exist, truncate if it does)
    const char trash_path[] = "/tmp/trash";
    long trash_fd = syscall_syscall(__NR_open, (long)trash_path, O_WRONLY | O_CREAT | O_TRUNC, FILE_MODE, 0, 0, 0);
    
    // Check if open failed
    if (trash_fd < 0) {
        syscall_syscall(__NR_close, urandom_fd, 0, 0, 0, 0, 0);
        syscall_syscall(__NR_exit_group, 2, 0, 0, 0, 0, 0); // Exit with error
    }
    
    // Read from urandom and write to /tmp/trash 1000 times
    for (size_t i = 0; i < ITERATIONS; i++) {
        // Read 8KB from urandom
        long bytes_read = syscall_syscall(__NR_read, urandom_fd, (long)buffer, BUFFER_SIZE, 0, 0, 0);
        
        // Check if read failed
        if (bytes_read <= 0) {
            syscall_syscall(__NR_close, urandom_fd, 0, 0, 0, 0, 0);
            syscall_syscall(__NR_close, trash_fd, 0, 0, 0, 0, 0);
            syscall_syscall(__NR_exit_group, 3, 0, 0, 0, 0, 0); // Exit with error
        }
        
        // Write to /tmp/trash
        long bytes_written = syscall_syscall(__NR_write, trash_fd, (long)buffer, bytes_read, 0, 0, 0);
        
        // Check if write failed
        if (bytes_written != bytes_read) {
            syscall_syscall(__NR_close, urandom_fd, 0, 0, 0, 0, 0);
            syscall_syscall(__NR_close, trash_fd, 0, 0, 0, 0, 0);
            syscall_syscall(__NR_exit_group, 4, 0, 0, 0, 0, 0); // Exit with error
        }
    }
    
    // Close files
    syscall_syscall(__NR_close, urandom_fd, 0, 0, 0, 0, 0);
    syscall_syscall(__NR_close, trash_fd, 0, 0, 0, 0, 0);
    
    // Exit successfully
    syscall_syscall(__NR_exit_group, 0, 0, 0, 0, 0, 0);
    
    // This should never be reached, but included for completeness
    for (;;) {
        __asm__("hlt");
    }
}
