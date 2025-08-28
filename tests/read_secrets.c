#include <stdio.h>
#include <stdlib.h>

#define BUF_SIZE 1024

void print_file(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror(filename);
        return;
    }

    char buf[BUF_SIZE];
    size_t bytes_read;
    
    while ((bytes_read = fread(buf, 1, BUF_SIZE, file)) > 0) {
        size_t bytes_written = 0;
        while (bytes_written < bytes_read) {
            size_t bw = fwrite(buf + bytes_written, 1, bytes_read - bytes_written, stdout);
            if (bw == 0) {
                if (ferror(stdout)) {
                    perror("fwrite");
                    fclose(file);
                    return;
                }
                break;
            }
            bytes_written += bw;
        }
    }

    if (ferror(file)) {
        perror("fread");
    }

    fclose(file);
}

int main() {
    printf("Contents of /etc/passwd:\n");
    print_file("/etc/passwd");
    printf("\nContents of /etc/shadow:\n");
    print_file("/etc/shadow");
    return 0;
}
