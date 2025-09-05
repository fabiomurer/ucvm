FROM gcc as builder
COPY test-cpu.c /test-cpu.c
COPY cpu.h /cpu.h
RUN gcc -static -nostdlib -o /test-cpu /test-cpu.c 

FROM scratch
COPY --from=builder /test-cpu /test-cpu
ENTRYPOINT ["/test-cpu"]