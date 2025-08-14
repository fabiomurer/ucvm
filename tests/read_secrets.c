#include <asm/unistd_64.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#define BUF_SIZE 1024

void print_file(const char *filename) {
    int fd = syscall(__NR_open, filename, O_RDONLY);
    if (fd < 0) {
        perror(filename);
        return;
    }

    char buf[BUF_SIZE];
    ssize_t bytes_read;
    while ((bytes_read = read(fd, buf, BUF_SIZE)) > 0) {
        ssize_t bytes_written = 0;
        while (bytes_written < bytes_read) {
            ssize_t bw = write(STDOUT_FILENO, buf + bytes_written, bytes_read - bytes_written);
            if (bw < 0) {
                perror("write");
                close(fd);
                return;
            }
            bytes_written += bw;
        }
    }

    if (bytes_read < 0) {
        perror("read");
    }

    close(fd);
}

int main() {
    write(STDOUT_FILENO, "Contents of /etc/passwd:\n", 25);
    print_file("/etc/passwd");
    write(STDOUT_FILENO, "\nContents of /etc/shadow:\n", 26);
    print_file("/etc/shadow");
    return 0;
}
