# run gvisor

## install

```
(
  set -e
  ARCH=$(uname -m)
  URL=https://storage.googleapis.com/gvisor/releases/release/latest/${ARCH}
  wget ${URL}/runsc ${URL}/runsc.sha512 \
    ${URL}/containerd-shim-runsc-v1 ${URL}/containerd-shim-runsc-v1.sha512
  sha512sum -c runsc.sha512 \
    -c containerd-shim-runsc-v1.sha512
  rm -f *.sha512
  chmod a+rx runsc containerd-shim-runsc-v1
  sudo mv runsc containerd-shim-runsc-v1 /usr/local/bin
)
```

```
$ /usr/local/bin/runsc install
$ sudo systemctl reload docke
```

## config

```
$ cat /etc/docker/daemon.json 
{
    "runtimes": {
        "runsc-kvm": {
            "path": "/home/fabio/Documents/projects/gvisor/bin/runsc",

            "runtimeArgs": [
                "--platform=kvm"
            ]
        },
        "runsc-systrap": {
            "path": "/home/fabio/Documents/projects/gvisor/bin/runsc",
            "runtimeArgs": [
                "--platform=systrap"
            ]
        }
    }
}
```

## build images

es.
```
docker build -f hello.dockerfile -t  hello-oci .
```

## run
es.
```
docker run --runtime=runsc-systrap --rm test-syscall-oci
docker run --runtime=runsc-kvm --rm test-syscall-oci
```