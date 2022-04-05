if [ $# -lt 2 ]; then
    echo "Input arguments missing."
    echo "arg1: hyp root directory."
    echo "arg2: host kernel build output root directory."
    echo "Fex. ./imx8qmmek-docker-run.sh <path>/kvms <path to kernel build output root>"
    exit 1
fi

export HYP_BUILD_ROOT=$1
export HOST_KERNEL_DIR=$2
export PLATFORM=nxp
export CHIPSET=imx8qm
export PRODUCT=imx8qmmek

docker run -it --rm \
		-v ${HOST_KERNEL_DIR}:/kernel_dir \
		-v ${HYP_BUILD_ROOT}:/hyp \
		--env PLATFORM=${PLATFORM} \
		--env CHIPSET=${CHIPSET} \
		--env PRODUCT=${PRODUCT} \
		--env KERNEL_DIR=/kernel_dir \
		--cap-add=SYS_ADMIN --privileged=true \
		kvms
