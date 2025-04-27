# UCVM 
run programs in a KVM virtual machine without an os

## Build

### preparation

```bash
mkdir ucvm_
mkdir build
cd ucvm_
git clone https://github.com/fabiomurer/ucvm.git
cd ucvm
git submodule init
git submodule update
```

### build
in `build/` folder
```bash
cmake ../ucvm/ -DCMAKE_BUILD_TYPE=Release

# for the debug version
cmake ../ucvm/

make
```

### formatting and linting
in `build/` folder
```bash
make format
make lint
```
