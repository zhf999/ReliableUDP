# 可靠传输协议RUDP

本项目使用Linux内核模块实现，由于其中一部分函数在内核中未被导出，所以需要配合[此仓库](https://github.com/zhf999/Linux-6.5.1-zhf)的内核版版本使用

测试程序可以使用[RUDP_test](https://github.com/zhf999/RUDP_test2)，也可以作为参考例程来使用。若想要自行编写使用本协议的代码，只需如下形式创建套接字即可：
```
#define IPPROTO_RUDP 141
int fd = socket(PF_INET,SOCK_DGRAM,IPPROTO_RUDP);
```
目前仅实现`sendto`和`recvfrom`系统调用，其它调用将使用UDP的接口。