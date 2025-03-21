# perf

- get kvm event num `sudo perf stat -e 'kvm:*' ..`'

## cpu cache:
- done but bho

## hugepages:
- bisogna essere amministratori per montare il filesystem hugetln [link](https://www.kernel.org/doc/html/latest/admin-guide/mm/hugetlbpage.html#using-huge-pages)

## avx make vmexit (bho)

## pin vcpu to cpu
increase of perfromances


## test

run with `bash tests/benchmark.sh program`

### 2025.03.20
### cpu

| Command | Mean [ms] | Min [ms] | Max [ms] | Relative |
|:---|---:|---:|---:|---:|
| `./tests/test-cpu` | 495.5 ± 36.8 | 458.7 | 582.4 | 1.01 ± 0.11 |
| `./release_build/ucvm -- ./tests/test-cpu` | 543.9 ± 51.4 | 500.8 | 644.3 | 1.11 ± 0.14 |
| `./release_build/ucvm -p0 -- ./tests/test-cpu` | 539.0 ± 59.8 | 482.2 | 651.5 | 1.10 ± 0.15 |
| `umvu ./tests/test-cpu` | 497.9 ± 32.1 | 469.8 | 557.9 | 1.02 ± 0.11 |
| `umvu -S ./tests/test-cpu` | 490.4 ± 40.1 | 456.3 | 573.5 | 1.00 |

```
Summary
  umvu -S ./tests/test-cpu ran
    1.01 ± 0.11 times faster than ./tests/test-cpu
    1.02 ± 0.11 times faster than umvu ./tests/test-cpu
    1.10 ± 0.15 times faster than ./release_build/ucvm -p0 -- ./tests/test-cpu
    1.11 ± 0.14 times faster than ./release_build/ucvm -- ./tests/test-cpu
```

### syscalls

| Command | Mean [ms] | Min [ms] | Max [ms] | Relative |
|:---|---:|---:|---:|---:|
| `./tests/test-syscall` | 11.3 ± 2.7 | 7.0 | 21.3 | 1.00 |
| `./release_build/ucvm -- ./tests/test-syscall` | 444.7 ± 7.6 | 430.6 | 456.2 | 39.50 ± 9.59 |
| `./release_build/ucvm -p0 -- ./tests/test-syscall` | 426.6 ± 18.4 | 390.2 | 451.5 | 37.90 ± 9.32 |
| `umvu ./tests/test-syscall` | 533.9 ± 54.4 | 440.6 | 618.9 | 47.44 ± 12.46 |
| `umvu -S ./tests/test-syscall` | 1079.2 ± 115.4 | 835.0 | 1164.1 | 95.88 ± 25.37 |

```
Summary
  ./tests/test-syscall ran
   37.90 ± 9.32 times faster than ./release_build/ucvm -p0 -- ./tests/test-syscall
   39.50 ± 9.59 times faster than ./release_build/ucvm -- ./tests/test-syscall
   47.44 ± 12.46 times faster than umvu ./tests/test-syscall
   95.88 ± 25.37 times faster than umvu -S ./tests/test-syscall
```

### io

| Command | Mean [ms] | Min [ms] | Max [ms] | Relative |
|:---|---:|---:|---:|---:|
| `./tests/test-io` | 157.5 ± 13.1 | 148.7 | 184.6 | 1.00 |
| `./release_build/ucvm -- ./tests/test-io` | 335.7 ± 14.7 | 308.1 | 353.1 | 2.13 ± 0.20 |
| `./release_build/ucvm -p0 -- ./tests/test-io` | 302.9 ± 14.3 | 287.0 | 326.2 | 1.92 ± 0.18 |
| `umvu ./tests/test-io` | 335.7 ± 78.1 | 240.5 | 471.9 | 2.13 ± 0.53 |
| `umvu -S ./tests/test-io` | 441.2 ± 91.9 | 306.4 | 601.5 | 2.80 ± 0.63 |


```
Summary
  ./tests/test-io ran
    1.92 ± 0.18 times faster than ./release_build/ucvm -p0 -- ./tests/test-io
    2.13 ± 0.20 times faster than ./release_build/ucvm -- ./tests/test-io
    2.13 ± 0.53 times faster than umvu ./tests/test-io
    2.80 ± 0.63 times faster than umvu -S ./tests/test-io
```