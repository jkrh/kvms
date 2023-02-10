This docker environment is to ease up building and running the kvms hypervisor.
By using the docker environment user do not need to install all the
dependencies and tools to the host.

See https://docs.docker.com/engine/install/ and
https://docs.docker.com/engine/install/linux-postinstall/ for docker engine
setup.

Start by getting your copy of kvms:
```
git clone https://github.com/jkrh/kvms.git
```
Go to the docker folder.
```
cd kvms/docker
```
Copy your host gitconfig, or create a stripped down version:

```
cp ~/.gitconfig gitconfig
```

Your .gitconfig file should contain at least

```
[user]
     name = Your name
     email = yourname@email.invalid
```

Build the docker image for virt
```
./virt-docker-build.sh
```
Build the docker image for imx8qmmek
```
./imx8qmmek-docker-build.sh
```

Building kvms for virt machine use virt-docker-run.sh:
```
./virt-docker-run.sh /home/me/kvms /home/me/kvms/oss/linux
```

For building NXP imx8qmmek use the imx8qmmek-docker-run.sh:
./imx8qmmek-docker-run.sh <kvms root folder> <kernel root folder>
For example:
```
./imx8qmmek-docker-run.sh /home/me/kvms /home/me/imx8kernel
```

Enter the hyp folder mounted by docker
```
cd hyp
```
Make. First time it will take long time to build: It will fetch and
build all the tools needed for building and running the kvms hypervisor
code. The following builds will be faster since only the kvms hypervisor
itself is being built.
```
make
```
Or debug build with host locks enabled
```
DEBUG=1 make
```
Or debug build with host locks disabled
```
DEBUG=2 make
```
Clean
```
make clean
```
Make qemu-for-android (Optional).
```
make android-qemu
```
If make fails due to permission issues, try running the docker image
with additional parameters '--cap-add=SYS_ADMIN --privileged=true'.

If there has been updates in kvms repository submodules you may need to
rebuild tools:
```
make tools-clean
make tools
```

Sometimes when running on arm64 hardware it is convenient to use static qemu-system-aarch64. Building static qemu is supported by running:
```
STATIC=1 make target-qemu
```

Ubuntu 22 environment is using OpenSSL version 3.0+ which can break some of the tooling that depends
on the older versions. In that case you can specify an additional argument to the docker build script,
e.g. for using `openssl-1.1.1t`

```
--build-arg OPENSSL=openssl-1.1.1t
```
