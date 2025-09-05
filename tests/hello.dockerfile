FROM gcc as builder
COPY hello.c /hello.c
COPY syscall.h /syscall.h
RUN gcc -g -static -nostdlib -o /hello /hello.c  

FROM scratch
COPY --from=builder /hello /hello
ENTRYPOINT ["/hello"]