CONFIG_MODULE_SIG=n
CONFIG_MODULE_SIG_ALL=n


obj-m += RUDP.o
RUDP-objs := RUDP_mod.o RUDP_imp.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
ins:
	sudo insmod RUDP.ko
rm:
	sudo rmmod RUDP
retry:
	sudo rmmod RUDP
	make
	sudo insmod RUDP.ko
c:
	/home/hfzhou/CLionProjects/RUDP_tests/cmake-build-debug/client
s:
	/home/hfzhou/CLionProjects/RUDP_tests/cmake-build-debug/server
