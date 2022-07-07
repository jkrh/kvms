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

Build the docker image
```
docker build --build-arg userid=$(id -u) --build-arg groupid=$(id -g) --build-arg username=$(id -un) -t kvms .
```
Building kvms for virt machine:
```
export HYP_BUILD_ROOT=<kvms root folder>
docker run -it --rm \
		-v $HYP_BUILD_ROOT:/hyp \
		--env PLATFORM=virt \
		kvms
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