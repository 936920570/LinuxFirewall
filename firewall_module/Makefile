MODULE	= myfw

SRC := mod_install.c source/FWLogs.c source/FWRules.c source/hook.c source/netlink_k.c source/userOp.c source/connect.c source/nat.c source/myhash.c

KDIR := /lib/modules/$(shell uname -r)/build

EXTRA_CFLAGS := -I$(src)/headers

$(MODULE)-objs = $(SRC:.c=.o)
obj-m := $(MODULE).o
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules 

install:
	insmod $(PWD)/$(MODULE).ko
	$(MAKE) clean

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) modules clean
	rm -rf modules.order
	rm -f *.symvers
