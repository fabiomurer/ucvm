FROM gcc as builder
COPY test-syscall.c /test-syscall.c
COPY syscall.h /syscall.h
RUN gcc -static -nostdlib -o /test-syscall /test-syscall.c 

FROM scratch
COPY --from=builder /test-syscall /test-syscall
ENTRYPOINT ["/test-syscall"]