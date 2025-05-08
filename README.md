# UCVM 
run programs in a KVM virtual machine without an os

## Usage

```
$ ./ucvm --help
Usage: ucvm [OPTION...] [ARGS...]
Run user-mode code in a kvm vm

  -d, --debug=HOST:PORT      Enable debug mode with specified server
  -p, --pin=CORE             Pin to specified CPU core
  -t, --trace                Enable trace mode
  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version

Mandatory or optional arguments to long options are also mandatory or optional
for any corresponding short options.

Report bugs to https://github.com/fabiomurer/ucvm.
```

## Runnin tests

compile test:
```bash
# in ucvm/tests
make

# run it
./ucvm -t -- [test_name] # for ex. ./hello
```

## Debugging virtualized program with gdb
GDB support is only partial (some commands are not yet supported)

For example debug the test `hello`

in one terminal start `ucvm` with debug option
```bash
# in debug/
./ucvm --debug="127.0.0.1:1234" -t -- ../ucvm/tests/hello
```

in one terminal run gdb in remote mode
```
# in ucvm/tests/
gdb
(gdb) file hello
Reading symbols from hello...
(gdb) target remote 127.0.0.1:1234
Remote debugging using 127.0.0.1:1234
_start () at hello.c:21
21	void __attribute__((noreturn)) __attribute__((section(".start"))) _start(void) {
...
```

## Benchmarking

For benchmarking this implementation a script is provided.

Dependencies
- [hyperfine](https://github.com/sharkdp/hyperfine)
- [vuos](https://github.com/virtualsquare/vuos)

first build `ucvm` in `release` mode
```bash
# in ucvm/tests
$ bash benchmark.bash [test-name] # es ./hello
```

## Build

### preparation

```bash
mkdir ucvm_
cd ucvm_
mkdir debug
mkdir release
git clone https://github.com/fabiomurer/ucvm.git
cd ucvm
git submodule init
git submodule update
```

directory tree should look like this:
```
.
└── ucvm_
    ├── debug
    ├── release
    └── ucvm
```

### build

### release
in `release/` folder
```bash
cmake ../ucvm/ -DCMAKE_BUILD_TYPE=Release
make
```

### debug
in `debug/` folder
```bash
cmake ../ucvm/
make
```

### formatting and linting
in `debug/` or `release/` folder
```bash
make format
make lint
```
