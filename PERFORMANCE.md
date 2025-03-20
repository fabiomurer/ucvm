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

```bash
hyperfine -i --export-markdown /tmp/test-cpu.md './tests/test-cpu' \
'./release_build/ucvm -- ./tests/test-cpu' \
'./release_build/ucvm -p0 -- ./tests/test-cpu' \
'umvu ./tests/test-cpu' \
'umvu -S ./tests/test-cpu'
```


```bash
hyperfine -i --export-markdown /tmp/test-syscall.md './tests/test-syscall' \
'./release_build/ucvm -- ./tests/test-syscall' \
'./release_build/ucvm -p0 -- ./tests/test-syscall' \
'umvu ./tests/test-syscall' \
'umvu -S ./tests/test-syscall'
```

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
