# kvm hardware

## cpu extensions

- xcr0 support `0x1f`: `X87` `SSE` `AVX` `BNDREG` `BNDCSR` `opmask` -> `AVX-512` not supported

## !! watch cpu register initialization value
has to be the same as when linux runs it.