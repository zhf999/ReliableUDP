#define IPPROTO_RUDP 141
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <net/protocol.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/inet_common.h>
#include <net/udp.h>
#include <linux/random.h>
#include <linux/inet.h>

enum rudp_type
{
	RUDP_TYPE_DATA,
	RUDP_TYPE_SYN,
	RUDP_TYPE_SYNACK,
	RUDP_TYPE_ACK,
	RUDP_TYPE_WIN,
};

enum rsock_state
{
	RUDP_STATE_CLOSED,
	RUDP_STATE_LISTEN,
	RUDP_STATE_SYN_SENT,
	RUDP_STATE_SYN_RECV,
	RUDP_STATE_ESTABLISHED,
	RUDP_STATE_SILENT,
	RUDP_STATE_FINISHED,
};

#pragma pack(1)
 
struct RUDP_header{
	struct udphdr uhdr;
	unsigned int seq,ack;
	short checksum,window;
	short len;
	enum rudp_type type:8;
};

#pragma pack()

struct rudp_sock{
	// extend from udp sock
	struct udp_sock usock;
	// the next seq to send and the last seq to receive
	unsigned int send_next_seq,last_ack;

	struct timer_list retransmit_timer, delack_timer;
	long retrans_timeout;
	long max_retrans_time;
	// how many packet are not acknowledged
	int in_flight;
	// max count of in-flight packet
	int win_size;
	// max count of in-queue packet
	int buf_size;
	// how many packet are in packet
	int in_queue;
	bool isClient,isConnected;
	enum rsock_state state;

	// all sent packet are add to this queue
	struct sk_buff_head	out_queue;

	// how many packet are not acked continuely
	int continue_nack,
	// congestion control: when win_size is greater then thresh, it will increase by 2 instead of by multiplying
	int thresh;
};

struct rudp_skb_cb {
	//Specific to UDP
        union {
             struct inet_skb_parm    h4;
#if IS_ENABLED(CONFIG_IPV6)
             struct inet6_skb_parm   h6;
#endif
        } header;
        __u16   cscov;
        __u8    partial_cov;

	//Specific to RUDP

};

#define RUDP_SKB_CB(__skb)	((struct rudp_skb_cb *)((__skb)->cb)) 

static inline struct rudp_sock *rudp_sk(const struct sock *sk)
{
	return (struct rudp_sock *)sk;
}

static inline struct RUDP_header *rudp_hdr(const struct sk_buff *skb)
{
	return (struct RUDP_header *)skb_transport_header(skb);
}

int rudp_init(struct sock *sk);
// deprecated
int rudp_connect(struct sock *sk,struct sockaddr *uaddr,int addr_len);

// this will be called when sendto SYSCALL is called
int rudp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);
// this will be called when recvfrom SYSCALL is called.
int rudp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags,
		int *addr_len);
// this will be called when close SYSCALL is called
void rudp_close(struct sock *sk,long timeout);

// this will be called when a new packet is delivered from IP layer
int rudp_rcv(struct sk_buff *skb);
// this will be called when a new packet is an error
int rudp_err(struct sk_buff *skb, u32 info);

// deprecated
int rudp_unicast_rcv_skb(struct sock *sk, struct sk_buff *skb);
// called by rudp_rcv, process different packet types
int rudp_unicast_rcv_skb_nc(struct sock *sk, struct sk_buff *skb); // no connection version

// deprecated
int rudp_send_syn(struct sock *sk, struct sockaddr *uaddr);
// deprecated
int rudp_send_synack(struct sock *sk, struct sockaddr *uaddr,struct sk_buff *skb);
// send an ack packet to peer
int rudp_send_ack(struct sock *sk, unsigned int ackid);
// this function will be call when an ack packet is received, it will remove
// packet with specified ack to avoid retransmitting
int rudp_rcv_ack(struct sock *sk, unsigned int ackid);

// deprecated
long inet_wait_for_connect(struct sock *sk, long timeo, int writebias);

// retransmit function
void retransmit_handler(struct timer_list *t);
// delay ack, this is to avoid sending to many ack packet in network
void delack_handler(struct timer_list *t);

// timer management
void reset_rudp_xmit_timer(struct sock *sk,long delay);
void clear_rudp_xmit_timer(struct sock *sk);
void reset_rudp_delack_timer(struct sock *sk, long delay);
void clear_rudp_delack_timer(struct sock *sk);

// make skb to hold data
struct sk_buff *rudp_ip_make_skb(struct sock *sk, int length);
int __rudp_make_skb(struct sock *sk,struct sk_buff_head *queue,struct inet_cork *cork,int length);

// send out a skb
int rudp_send_skb(struct net *net, struct flowi4 *fl4,struct sk_buff *skb);
// add a skb to send queue, if queue length is greater then buf_size, process will block util
// send queue is flushed out
int rudp_add_to_snd_queue(struct sk_buff *skb);
// is out_queue has space to hold more skb, this function will try to send a skb in send_queue,
// then move this skb to out_queue for retransmitting
int try_flush_send_queue(struct sock *sk);

// increase and decrease window size
void win_inc(struct sock *sk);
void win_dec(struct sock *sk);
