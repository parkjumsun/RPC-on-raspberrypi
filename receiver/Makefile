obj-m := rpc_raspberry_receiver.o
KERNDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) M=$(PWD) $(ARM) modules
	arm-linux-gnueabi-gcc rpc_raspberry_receiver_lib.c -o rpc_raspberry_receiver
default:
	$(MAKE) -C $(KERNDIR) M=$(PWD) modules
