obj-m += mctp_bridge.o

KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all: demo send bridge udp_echo

module:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules

clean:
	rm -f demo send bridge udp_echo *.o
	@if [ -d "$(KERNEL_DIR)" ]; then $(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean; fi


demo:
	gcc demo.c pldm.c -o demo

bridge:
	gcc bridge.c pldm.c -o bridge

send:
	gcc send.c -o send

udp_echo:
	gcc udp_echo.c -o udp_echo
