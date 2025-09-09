FROM gcc as builder
COPY test-io.c /test-io.c
COPY syscall.h /syscall.h
RUN gcc -static -nostdlib -o /test-io /test-io.c 

FROM scratch
COPY --from=builder /test-io /test-io
ENTRYPOINT ["/test-io"]