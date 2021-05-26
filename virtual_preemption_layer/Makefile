# If KERNELRELEASE is defined, we've been invoked from the
# kernel build system and can use its language.
ifneq ($(KERNELRELEASE),) 
	obj-m := vpl.o
# Otherwise we were called directly from the command
# line; invoke the kernel build system.
else
KERNELDIR ?= /lib/modules/$(shell uname -r)/build 
 #第一中找内核路径方法
#KERNELDIR ?= /usr/src/"linux-headers-$(shell uname -r)" #第二种找内核路径的方法，实质也是前一种方法的链接
PWD := $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules  
    #此处巧妙的运用了 “-C” 实现了二次调用Makefile，注意make前要有”tab“按键
modules_install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install
clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean 

endif