#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <net/protocol.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/inet_common.h>
#include <net/udp.h>
#include "RUDP.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Zhou hongfeng");
MODULE_DESCRIPTION("RUDP module");
MODULE_VERSION("0.01");

static struct proto rudp_prot;
static struct net_protocol rudp_protocol;

// inet_protosw structure, this structure will be used when registering RUDP
static struct inet_protosw RUDP_inetsw =
{
		.type = SOCK_DGRAM,
		.protocol = IPPROTO_RUDP,
		.prot = &rudp_prot,
		.ops = &inet_dgram_ops,
		.flags = INET_PROTOSW_REUSE,
};


void init_RUDP(void)
{
	// make RUDP behavior like UDP
	rudp_prot = udp_prot;
	// below lines set RUDP handles to our function
	memcpy(rudp_prot.name,"RUDP\0",5);
	rudp_prot.sendmsg = rudp_sendmsg;
	rudp_prot.recvmsg = rudp_recvmsg;
	rudp_prot.init = rudp_init;
	rudp_prot.connect = rudp_connect;
	rudp_prot.close = rudp_close;

	// when creating a new socket, kernel will allocate a space whose size is obj_size
	// this allows us to cast pointer type from struct sock* to struct rudp_sock* safely 
	rudp_prot.obj_size = sizeof(struct rudp_sock);

	// set rudp_protocol structure
	// when IP layer receives a packet, the packet will be deliver to rudp_rcv
	rudp_protocol.handler = rudp_rcv;
	rudp_protocol.err_handler = rudp_err;
	rudp_protocol.no_policy = 1;
	return ;
}

// this is the entrance of kernel module
static int __init RUDP_mod_init(void) {
	printk(KERN_INFO "Hello, World!22\n");
	init_RUDP();
	int res;
	// rigister a protocol
	res =  proto_register(&rudp_prot,1);
	if(res<0)
		printk(KERN_INFO "proto_register error!\n");		
	// register protocol handles
	res = inet_add_protocol(&rudp_protocol,IPPROTO_RUDP);
	if(res<0)
		printk(KERN_INFO "proto add error!\n");
	
	// register protocol
	inet_register_protosw(&RUDP_inetsw);
	return 0;
}

static void __exit RUDP_mod_exit(void) {
	printk(KERN_INFO "Goodbye, World!\n");
	proto_unregister(&rudp_prot);	
	inet_del_protocol(&rudp_protocol,IPPROTO_RUDP);
	inet_unregister_protosw(&RUDP_inetsw);
	return ;
}


module_init(RUDP_mod_init);

module_exit(RUDP_mod_exit);
