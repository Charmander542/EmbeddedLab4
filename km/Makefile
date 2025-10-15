ifneq ($(KERNELRELEASE),)
    # We are inside the kernel build system
    obj-m := mytraffic.o
else
    # Normal make: cross-compile
    KERNELDIR := $(EC535)/bbb/stock/stock-linux-4.19.82-ti-rt-r33
    PWD       := $(shell pwd)
    ARCH      := arm
    CROSS     := arm-linux-gnueabihf-

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS) clean

endif
