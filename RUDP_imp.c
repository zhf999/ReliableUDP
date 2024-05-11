
#include "RUDP.h"

int cnt = 0;

int rudp_init(struct sock *sk)
{
	printk(KERN_INFO "Init sock!\n");
	struct rudp_sock *rsock = rudp_sk(sk);
	skb_queue_head_init(&sk->sk_write_queue);
	skb_queue_head_init(&rsock->out_queue);

	rsock->win_size = 1;
	rsock->buf_size = 16;
	rsock->in_flight = 0;
	rsock->in_queue = 0;

	timer_setup(&rsock->retransmit_timer,retransmit_handler,0);
	timer_setup(&rsock->delack_timer,delack_handler,0);

	rsock->retrans_timeout = HZ/100;
	rsock->last_ack = 0;
	rsock->max_retrans_time = 5;

	rsock->continue_nack = 0;
	rsock->thresh = 32;

	// initialize seq number
	get_random_bytes(&rsock->send_next_seq,sizeof(rsock->send_next_seq));
	return udp_prot.init(sk);
}

void retransmit_handler(struct timer_list *t)
{
	struct rudp_sock *rsk =
			from_timer(rsk, t, retransmit_timer);
	struct sock *sk = (struct sock*)rsk;

	if(skb_queue_empty(&rsk->out_queue))
		return ;

	// button half sock lock
	bh_lock_sock(sk);
	if(sock_owned_by_user(sk))
	{
		// if sock is hold by user process, call it later
		printk(KERN_INFO "sock is locked!\n");
		reset_rudp_xmit_timer(sk,rsk->retrans_timeout>>1);
		bh_unlock_sock(sk);
		sock_put(sk);
		return ;
	}
	struct sk_buff *pskb,*tmp;
	int cnt = 0;
	// retransmit all packet in out_queue
	skb_queue_walk(&rsk->out_queue,pskb)
	{
		cnt++;
		struct RUDP_header *rh = rudp_hdr(pskb);
		printk(KERN_INFO "retransmit packet: seq=%u ack=%u\n",ntohl(rh->seq),ntohl(rh->ack));
		tmp = skb_clone(pskb,GFP_ATOMIC);
		ip_send_skb(sock_net(sk),tmp);
	}
	
	// decrease window size
	win_dec(sk);
	bh_unlock_sock(sk);

	// if out_queue is not empty, retransmit handler will be called again
	if(!skb_queue_empty(&rsk->out_queue))
		reset_rudp_xmit_timer(sk,rsk->retrans_timeout);

	sock_put(sk);
}

void delack_handler(struct timer_list *t)
{
	struct rudp_sock *rsk =
			from_timer(rsk, t, delack_timer);
	struct sock *sk = (struct sock*)rsk;	

	bh_lock_sock(sk);
	if(sock_owned_by_user(sk))
	{
		// if sock is hold by user process, call it later
		printk(KERN_INFO "sock is locked!\n");
		reset_rudp_delack_timer(sk,rsk->retrans_timeout>>1);
		bh_unlock_sock(sk);
		sock_put(sk);
		return ;
	}
	// send an ack
	if(rsk->isConnected&&rsk->last_ack!=0)
		rudp_send_ack(sk,rsk->last_ack);
	bh_unlock_sock(sk);
	sock_put(sk);
	return ;
}

void reset_rudp_xmit_timer(struct sock *sk,long delay)
{
	struct rudp_sock *rsk = (struct rudp_sock*)sk;
	sk_reset_timer(sk,&rsk->retransmit_timer,jiffies + delay);
}

void clear_rudp_xmit_timer(struct sock *sk)
{
	struct rudp_sock *rsk = (struct rudp_sock *)sk;
	sk_stop_timer_sync(sk,&rsk->retransmit_timer);
	// del_timer_sync(&rsk->retransmit_timer);
}

void reset_rudp_delack_timer(struct sock *sk, long delay)
{
	struct rudp_sock * rsk = rudp_sk(sk);
	sk_reset_timer(sk,&rsk->delack_timer,jiffies+delay);
}

void clear_rudp_delack_timer(struct sock *sk)
{
	struct rudp_sock *rsk = (struct rudp_sock *)sk;
	sk_stop_timer_sync(sk,&rsk->delack_timer);
}


// deprecated
int rudp_connect(struct sock *sk,struct sockaddr *uaddr,int addr_len)
{
	long timeo = rudp_sk(sk)->retrans_timeout*10;
	struct sockaddr_in * sin = (struct sockaddr_in*)uaddr;
	if(sin->sin_addr.s_addr==INADDR_ANY)
	{
		printk(KERN_INFO "RUDP start listen!\n");
		lock_sock(sk);
		rudp_sk(sk)->state = RUDP_STATE_LISTEN;
		rudp_sk(sk)->isClient = false;
		inet_wait_for_connect(sk,timeo,0);
		release_sock(sk);
		return 0;
	}	
	int res;
	printk(KERN_INFO "RUDP connection initiated....\n");
	rudp_sk(sk)->isClient = true;
	res = ip4_datagram_connect(sk, uaddr, addr_len);
	lock_sock(sk);
	rudp_sk(sk)->state = RUDP_STATE_SYN_SENT;
	rudp_sk(sk)->isConnected = true;
	rudp_send_syn(sk,uaddr);
	inet_wait_for_connect(sk,timeo,0);
	printk(KERN_INFO "timeo=%ld\n",timeo);
	release_sock(sk);
	return res;
}

// deprecated
int rudp_send_syn(struct sock *sk, struct sockaddr *uaddr)
{
	struct rudp_sock *rsk = rudp_sk(sk);
	struct sockaddr_in *usin = (struct sockaddr_in *)uaddr;
	struct sk_buff *skb;
	struct inet_sock *inet = inet_sk(sk);
	
	skb = rudp_ip_make_skb(sk,0);
	struct RUDP_header * rudphdr = rudp_hdr(skb);
	int offset = skb_transport_offset(skb);
	int len = skb->len - offset;

	struct udphdr *uh = udp_hdr(skb);
	uh->source = inet->inet_sport;
	uh->dest = (usin->sin_port);
	uh->len = htons(len);
	uh->check = 0;

	rudphdr->type = htons(RUDP_TYPE_SYN)>>8;
	rudphdr->seq = htonl(rsk->send_next_seq++);
	// printk(KERN_INFO "SYN seq=%u type=%x\n",rsk->send_next_seq-1,rudphdr->type);
	rudphdr->len = 0;

	rudp_add_to_snd_queue(skb);
	return 0;
}

long inet_wait_for_connect(struct sock *sk, long timeo, int writebias)
{
	DEFINE_WAIT_FUNC(wait, woken_wake_function);

	add_wait_queue(sk_sleep(sk), &wait);
	sk->sk_write_pending += writebias;
	sk->sk_wait_pending++;

	while (rudp_sk(sk)->state!=RUDP_STATE_ESTABLISHED) {
		// printk(KERN_INFO "sleep for a while\n");
		release_sock(sk);
		timeo = wait_woken(&wait, TASK_INTERRUPTIBLE, timeo);
		lock_sock(sk);
		if (signal_pending(current) || !timeo)
		{
			printk(KERN_INFO "a signal comes!3\n");
			break;
		}
			
	}
	remove_wait_queue(sk_sleep(sk), &wait);
	sk->sk_write_pending -= writebias;
	sk->sk_wait_pending--;
	return timeo;
}

int rudp_sendmsg_locked(struct sock *sk, struct msghdr *msg, size_t len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct udp_sock *up = udp_sk(sk);
	// struct rudp_sock *rup = rudp_sk(sk);
	DECLARE_SOCKADDR(struct sockaddr_in *, usin, msg->msg_name);
	struct flowi4 fl4_stack;
	struct flowi4 *fl4;
	int ulen = len;
	struct ipcm_cookie ipc;
	struct rtable *rt = NULL;
	int free = 0;
	int connected = 0;
	__be32 daddr, faddr, saddr;
	u8 tos, scope;
	__be16 dport;
	int err;
	int corkreq = READ_ONCE(up->corkflag) || msg->msg_flags&MSG_MORE;
	int (*getfrag)(void *, char *, int, int, int, struct sk_buff *);
	struct sk_buff *skb;
	struct ip_options_data opt_copy;

	if (len > 0xFFFF)
		return -EMSGSIZE;
	getfrag = ip_generic_getfrag;

	fl4 = &inet->cork.fl.u.ip4;
	ulen += sizeof(struct RUDP_header);

	if (usin) {
		if (msg->msg_namelen < sizeof(*usin))
			return -EINVAL;
		if (usin->sin_family != AF_INET) {
			if (usin->sin_family != AF_UNSPEC)
				return -EAFNOSUPPORT;
		}

		daddr = usin->sin_addr.s_addr;
		dport = usin->sin_port;
		if (dport == 0)
			return -EINVAL;
	} else {
		if (sk->sk_state != TCP_ESTABLISHED)
			return -EDESTADDRREQ;
		daddr = inet->inet_daddr;
		dport = inet->inet_dport;
		/* Open fast path for connected socket.
		   Route will not be used, if at least one option is set.
		 */
		connected = 1;
	}

	ipcm_init_sk(&ipc, inet);
	ipc.gso_size = READ_ONCE(up->gso_size);
	if (!ipc.opt) {
		struct ip_options_rcu *inet_opt;

		rcu_read_lock();
		inet_opt = rcu_dereference(inet->inet_opt);
		if (inet_opt) {
			memcpy(&opt_copy, inet_opt,
			       sizeof(*inet_opt) + inet_opt->opt.optlen);
			ipc.opt = &opt_copy.opt;
		}
		rcu_read_unlock();
	}

		saddr = ipc.addr;
	ipc.addr = faddr = daddr;

	if (ipc.opt && ipc.opt->opt.srr) {
		if (!daddr) {
			err = -EINVAL;
			goto out_free;
		}
		faddr = ipc.opt->opt.faddr;
		connected = 0;
	}
	tos = get_rttos(&ipc, inet);
	scope = ip_sendmsg_scope(inet, &ipc, msg);
	if (scope == RT_SCOPE_LINK)
		connected = 0;

	if (ipv4_is_multicast(daddr)) {
		if (!ipc.oif || netif_index_is_l3_master(sock_net(sk), ipc.oif))
			ipc.oif = inet->mc_index;
		if (!saddr)
			saddr = inet->mc_addr;
		connected = 0;
	} else if (!ipc.oif) {
		ipc.oif = inet->uc_index;
	} else if (ipv4_is_lbcast(daddr) && inet->uc_index) {
		/* oif is set, packet is to local broadcast and
		 * uc_index is set. oif is most likely set
		 * by sk_bound_dev_if. If uc_index != oif check if the
		 * oif is an L3 master and uc_index is an L3 slave.
		 * If so, we want to allow the send using the uc_index.
		 */
		if (ipc.oif != inet->uc_index &&
		    ipc.oif == l3mdev_master_ifindex_by_index(sock_net(sk),
							      inet->uc_index)) {
			ipc.oif = inet->uc_index;
		}
	}

	if (connected)
		rt = (struct rtable *)sk_dst_check(sk, 0);

	if (!rt) {
		struct net *net = sock_net(sk);
		__u8 flow_flags = inet_sk_flowi_flags(sk);

		fl4 = &fl4_stack;

		flowi4_init_output(fl4, ipc.oif, ipc.sockc.mark, tos, scope,
				   sk->sk_protocol, flow_flags, faddr, saddr,
				   dport, inet->inet_sport, sk->sk_uid);

		security_sk_classify_flow(sk, flowi4_to_flowi_common(fl4));
		rt = ip_route_output_flow(net, fl4, sk);
		if (IS_ERR(rt)) {
			err = PTR_ERR(rt);
			rt = NULL;
			if (err == -ENETUNREACH)
				IP_INC_STATS(net, IPSTATS_MIB_OUTNOROUTES);
			goto out;
		}

		err = -EACCES;
		if ((rt->rt_flags & RTCF_BROADCAST) &&
		    !sock_flag(sk, SOCK_BROADCAST))
			goto out;
		if (connected)
			sk_dst_set(sk, dst_clone(&rt->dst));
	}

	saddr = fl4->saddr;
	if (!ipc.addr)
		daddr = ipc.addr = fl4->daddr;

	/* Lockless fast path for the non-corking case. */
	if (!corkreq) {
		struct inet_cork cork;

		skb = ip_make_skb(sk, fl4, getfrag, msg, ulen,
				  sizeof(struct RUDP_header), &ipc, &rt,
				  &cork, msg->msg_flags);
		err = PTR_ERR(skb);
		if (!IS_ERR_OR_NULL(skb))
			err = rudp_send_skb(sock_net(sk), fl4, skb);
		goto out;
	}

out:
	ip_rt_put(rt);
out_free:
	if (free)
		kfree(ipc.opt);
	if (!err)
		return len;

	if (err == -ENOBUFS || test_bit(SOCK_NOSPACE, &sk->sk_socket->flags)) {
		UDP_INC_STATS(sock_net(sk),
			      UDP_MIB_SNDBUFERRORS, 0);
	}
	return err;
}

int rudp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	// lock_sock(sk);
	// printk("ref of rudp: %d\n",refcount_read(&sk->sk_refcnt));
	cnt++;
	int res = rudp_sendmsg_locked(sk,msg,len);
	// release_sock(sk);
	return res;
}

struct sk_buff *rudp_ip_make_skb(struct sock *sk, int length)
{
	struct inet_cork cork;
	struct sk_buff_head queue;
	struct ipcm_cookie ipc;
	struct rtable *rt;
	struct inet_sock *inet = inet_sk(sk);
	struct flowi4 *fl4 = &inet->cork.fl.u.ip4;
	int err;

	__skb_queue_head_init(&queue);

	rt = (struct rtable *)sk_dst_check(sk, 0);

	ipc.opt = NULL;
	// ipc.tx_flags = 1;
	ipc.ttl = 0;
	ipc.tos = -1;
	ipc.oif = sk->sk_bound_dev_if;
	ipc.addr = fl4->daddr;

	cork.flags = 0;
	cork.addr = 0;
	cork.opt = NULL;
	err = ip_setup_cork(sk, &cork, &ipc, &rt);
	if (err)
	{
		printk(KERN_INFO "err2=%d\n",err);
		return ERR_PTR(err);
	}
		

	err = __rudp_make_skb(sk, &queue, &cork, length);
	if (err) {                                              //if socket buffer allocation doesn't succeed, flush pending frames and return an error
		__ip_flush_pending_frames(sk, &queue, &cork);
		printk(KERN_INFO "err1\n");
		return ERR_PTR(err);
	}
	//data is copied to the socket buffer by the function ip_make_skb 
	struct sk_buff* skb =  __ip_make_skb(sk, fl4, &queue, &cork);
	skb->sk = sk;
	return skb;
}

int __rudp_make_skb(struct sock *sk,
			    struct sk_buff_head *queue,
			    struct inet_cork *cork,
			    int length)
{
	struct sk_buff *skb; //new buffer!
	char *data;
	int hh_len;
	int exthdrlen;
	int err;
	unsigned int fragheaderlen, fraglen, alloclen;
	struct rtable *rt = (struct rtable *)cork->dst;

	skb = skb_peek_tail(queue);

	exthdrlen = rt->dst.header_len;

	hh_len = LL_RESERVED_SPACE(rt->dst.dev);

	fragheaderlen = sizeof(struct iphdr);

	fraglen = sizeof(struct RUDP_header) + fragheaderlen;

	alloclen = fraglen;                

	alloclen += exthdrlen;              //extentions header 
	alloclen += rt->dst.trailer_len;    //destination trailer length
	alloclen += length;                 //length of packet (function parameter)

	//alloclen += 200;

	skb = sock_alloc_send_skb(sk,
			alloclen + hh_len + 15,
			0, &err);                   //socket allocation
	if (skb == NULL)                    //if problems...
		goto error;

	/*
	 *	Fill in the control structures
	 */
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum = 0;
	skb_reserve(skb, hh_len);
	skb_shinfo(skb)->tx_flags = cork->tx_flags;

	/*
	 *	Find where to start putting bytes.
	 */
	data = skb_put(skb, fraglen + exthdrlen);           //data after fraglen + exthdrlen
	skb_set_network_header(skb, exthdrlen);             //network header after exthdrlen
	skb->transport_header = (skb->network_header +      //transport header after IP header
				 fragheaderlen);
	/*
	 * Put the packet on the pending queue.
	 */
	__skb_queue_tail(queue, skb);

	return 0;

error:  //increase stats in case of error
	IP_INC_STATS(sock_net(sk), IPSTATS_MIB_OUTDISCARDS);
	return err;
}

int rudp_send_skb(struct net *net,struct flowi4 *fl4, struct sk_buff *skb)
{
	struct sock *sk = skb->sk;
	struct inet_sock *inet = inet_sk(sk);
	struct rudp_sock *rsock = rudp_sk(sk);
	struct udphdr *uh;
	struct RUDP_header *ruh;
	int offset = skb_transport_offset(skb);
	int len = skb->len - offset;

	/*
	 * Create a UDP header
	 */
	uh = udp_hdr(skb);
	uh->source = inet->inet_sport;
	uh->dest = fl4->fl4_dport;
	uh->len = htons(len);
	uh->check = 0;

	// Create a RUDP header
	ruh = rudp_hdr(skb);
	ruh->seq = htonl(rsock->send_next_seq++);
	ruh->type = htons(RUDP_TYPE_DATA);
	ruh->len = htons(len-sizeof(struct RUDP_header));

	// try to add this skb to send queue
	rudp_add_to_snd_queue(skb);
	return 0;
}

int rudp_add_to_snd_queue(struct sk_buff *skb)
{
	struct sock * sk = skb->sk;
	struct rudp_sock *rsock = rudp_sk(sk);
	if(sk==NULL)
	{
		printk("no sk!\n");
		return 0;
	}

	// if send_queue is full, block util there is enough space
	if(rsock->in_queue==rsock->buf_size)
	{
		DEFINE_WAIT_FUNC(wait, woken_wake_function);
		add_wait_queue(sk_sleep(sk), &wait);
		long timeo = 25*HZ;
		lock_sock(sk);
		while (rsock->in_queue>=rsock->buf_size) {
			// printk(KERN_INFO "sleep for a while\n");
			release_sock(sk);
			timeo = wait_woken(&wait, TASK_INTERRUPTIBLE, timeo);
			lock_sock(sk);
			if (signal_pending(current) || !timeo)
			{
				printk(KERN_INFO "a signal comes!4\n");
				break;
			}
		}
		release_sock(sk);
		remove_wait_queue(sk_sleep(sk), &wait);
		printk(KERN_INFO "put %u into quque!\n",htonl(rudp_hdr(skb)->seq));
	}

	// add a skb to send queue
	skb_queue_tail(&sk->sk_write_queue, skb);
	rsock->in_queue++;

	// check if more skb in send_queue can be send out
	try_flush_send_queue(sk);
	return 0;
}


int try_flush_send_queue(struct sock *sk)
{
	// printk(KERN_INFO "start to flush write queue\n");
	if(skb_queue_empty(&sk->sk_write_queue))
		return -1;
	
	struct rudp_sock *rsock = rudp_sk(sk);
	struct sk_buff *pskb,*skb,*temp;

	// disable soft interrupt
	local_bh_disable();
	if(skb_queue_empty(&rsock->out_queue)&&!skb_queue_empty(&sk->sk_write_queue))
	{
		reset_rudp_xmit_timer(sk,rudp_sk(sk)->retrans_timeout);
	}
	// if out queue is not full, send a skb from send_queue, then move it from
	// send_queue to out_queue
	skb_queue_walk_safe(&sk->sk_write_queue,pskb,temp)
	{
		if(rsock->in_flight>=rsock->win_size)
			break;
		skb = skb_clone(pskb,GFP_ATOMIC);
		ip_send_skb(sock_net(sk),skb);
		rsock->in_flight++;
		rsock->in_queue--;
		skb_unlink(pskb,&sk->sk_write_queue);
		skb_queue_tail(&rsock->out_queue,pskb);
		printk(KERN_INFO "flush : skb->type=%x seq=%u ack=%u\n",
			rudp_hdr(pskb)->type,ntohl(rudp_hdr(pskb)->seq),ntohl(rudp_hdr(pskb)->ack));		
	}
	local_bh_enable();	
	return 0;
}

int rudp_recvmsg_locked(struct sock *sk, struct msghdr *msg, size_t len, int flags,
		int *addr_len)
{
	// struct inet_sock *inet = inet_sk(sk);
	DECLARE_SOCKADDR(struct sockaddr_in *, sin, msg->msg_name);
	struct sk_buff *skb;
	unsigned int ulen, copied;
	int off, err, peeking = flags & MSG_PEEK;

	off = sk_peek_offset(sk, flags);
	// try to get a skb from receive_queue
	// when receive queue is empty, process blocks
	skb = __skb_recv_udp(sk, flags, &off, &err);
	if (!skb)
		return err;

	ulen = skb->len;
	copied = len;
	if (copied > ulen - off)
		copied = ulen - off;
	else if (copied < ulen)
		msg->msg_flags |= MSG_TRUNC;

	if (udp_skb_is_linear(skb))
		err = copy_linear_skb(skb, copied, off, &msg->msg_iter);
	else
		err = skb_copy_datagram_msg(skb, off, msg, copied);		    

	sock_recv_cmsgs(msg, sk, skb);

	/* Copy the address. */
	if (sin) {
		sin->sin_family = AF_INET;
		sin->sin_port = udp_hdr(skb)->source;
		sin->sin_addr.s_addr = ip_hdr(skb)->saddr;
		memset(sin->sin_zero, 0, sizeof(sin->sin_zero));
		*addr_len = sizeof(*sin);

		BPF_CGROUP_RUN_PROG_UDP4_RECVMSG_LOCK(sk,
						      (struct sockaddr *)sin);
	}
	err = copied;
	if (flags & MSG_TRUNC)
		err = ulen;

	// skb_free_datagram_locked(sk,skb);
	skb_consume_udp(sk, skb, peeking ? -err : err);
	return err;
}

int rudp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addrlen)
{
	// lock_sock(sk);
	int res = rudp_recvmsg_locked(sk,msg,len,flags,addrlen);
	// release_sock(sk);
	return res;
}

void rudp_close(struct sock *sk,long timeout)
{
	struct rudp_sock *rsock = rudp_sk(sk);
	// wait until all packet is acknowledged by peer
	DEFINE_WAIT_FUNC(wait, woken_wake_function);
	add_wait_queue(sk_sleep(sk), &wait);
	lock_sock(sk);
	while (!skb_queue_empty(&rsock->out_queue)) {
		printk(KERN_INFO "sleep for a while\n");
		release_sock(sk);
		wait_woken(&wait, TASK_INTERRUPTIBLE, MAX_SCHEDULE_TIMEOUT);
		lock_sock(sk);
		if (signal_pending(current))
		{
			printk(KERN_INFO "a signal comes!2\n");
			break;
		}
	}
	release_sock(sk);

	clear_rudp_xmit_timer(sk);

	printk(KERN_INFO "closing soket\n");
	printk("ref: %d\n",refcount_read(&sk->sk_refcnt));
	// skb_queue_purge(&sk->sk_receive_queue);
	// clean write queue
	skb_queue_purge(&sk->sk_write_queue);
	udp_prot.close(sk,timeout);
}

int rudp_rcv(struct sk_buff *skb)
{
	struct sock *sk;
	struct udphdr *uh;
	unsigned short ulen;
	// struct rtable *rt = skb_rtable(skb);
	__be32 saddr, daddr;
	struct net *net = dev_net(skb->dev);
	bool refcounted;
	struct udp_table* udptable = dev_net(skb->dev)->ipv4.udp_table;

	if (!pskb_may_pull(skb, sizeof(struct RUDP_header)))
		goto drop;		/* No space for header. */

	uh   = udp_hdr(skb);
	ulen = ntohs(uh->len);
	saddr = ip_hdr(skb)->saddr;
	daddr = ip_hdr(skb)->daddr;

	if (ulen > skb->len)
	{
		printk(KERN_INFO "short\n");
		goto short_packet;
	}
		

	if (ulen < sizeof(*uh) || pskb_trim_rcsum(skb, ulen))
		goto short_packet;

	const struct iphdr *iph = ip_hdr(skb);


	sk = skb_steal_sock(skb,&refcounted);
	if (sk) {
	//destination cache definition
		struct dst_entry *dst = skb_dst(skb);
		if (unlikely(rcu_dereference(sk->sk_rx_dst) != dst))
			udp_sk_rx_dst_set(sk, dst);

		int ret = rudp_unicast_rcv_skb(sk,skb);
		if(refcounted)
			sock_put(sk);
		return ret;
	}
	sk = __udp4_lib_lookup(dev_net(skb->dev), iph->saddr, uh->source,
				 iph->daddr, uh->dest, inet_iif(skb),
				 inet_sdif(skb), udptable, skb);

	if(sk)
		return rudp_unicast_rcv_skb_nc(sk,skb);
	
short_packet:
	net_dbg_ratelimited("UDP%s: short packet: From %pI4:%u %d/%d to %pI4:%u\n",
			    "",
			    &saddr, ntohs(uh->source),
			    ulen, skb->len,
			    &daddr, ntohs(uh->dest));

drop:
	__UDP_INC_STATS(net, UDP_MIB_INERRORS, false);
	kfree_skb_reason(skb, SKB_DROP_REASON_NOT_SPECIFIED);
	return 0;


}

int rudp_unicast_rcv_skb_nc(struct sock *sk, struct sk_buff *skb)
{
	__be32 saddr, daddr;
	saddr = ip_hdr(skb)->saddr;
	daddr = ip_hdr(skb)->daddr;
	struct sockaddr_in addrin;
	struct RUDP_header *rh = rudp_hdr(skb);
	struct udphdr *uh = udp_hdr(skb);
	enum rudp_type packet_type = ntohs(rh->type<<8);
	struct rudp_sock *rsk = rudp_sk(sk);

	addrin.sin_addr.s_addr = saddr;
	addrin.sin_port = (uh->source);
	addrin.sin_family = AF_INET;

	// before communicate, connect to peer (store peer address and port)
	if(!rsk->isConnected)
	{
		rsk->isConnected = true;
		ip4_datagram_connect(sk, (struct sockaddr *) &addrin, sizeof(addrin));
	}
	
	if(packet_type==RUDP_TYPE_DATA)
	{
		// the packet is what we expected
		if(ntohl(rh->seq)==rsk->last_ack+1||rsk->last_ack==0)
		{
			rsk->last_ack = ntohl(rh->seq);
			skb_pull(skb,sizeof(struct RUDP_header));
			// every packet we receive will delay ack sending
			reset_rudp_delack_timer(sk,rsk->retrans_timeout>>1);
			printk("a data packet comes:%u!\n",ntohl(rh->seq));
			rsk->continue_nack = 0;
			return sock_queue_rcv_skb(sk, skb);
		}
		else
		{
			// ack packet may get lost, if this occurs, we will receive unexpected packet
			// this scope avoid this situation
			rsk->continue_nack ++;
			if(rsk->continue_nack>=2)
				rudp_send_ack(sk,rsk->last_ack);
			return 0;
		}
	}
	
	// if receive a ack packet
	if(packet_type==RUDP_TYPE_ACK||packet_type==RUDP_TYPE_SYNACK)
	{
		printk(KERN_INFO "Received ack = %u!\n",ntohl(rh->ack));
		unsigned int ackid = ntohl(rh->ack);
		rudp_rcv_ack(sk,ackid);
		win_inc(sk);
		return 0;
	}

	return 0;	
}

// deprecated
int rudp_unicast_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	__be32 saddr, daddr;
	saddr = ip_hdr(skb)->saddr;
	daddr = ip_hdr(skb)->daddr;
	struct sockaddr_in addrin;
	struct RUDP_header *rh = rudp_hdr(skb);
	struct udphdr *uh = udp_hdr(skb);
	enum rudp_type packet_type = ntohs(rh->type<<8);
	struct rudp_sock *rsk = rudp_sk(sk);

	addrin.sin_addr.s_addr = saddr;
	addrin.sin_port = (uh->source);
	addrin.sin_family = AF_INET;

	if(!rsk->isConnected)
	{
		rsk->isConnected = true;
		ip4_datagram_connect(sk, (struct sockaddr *) &addrin, sizeof(addrin));
	}
	if(packet_type==RUDP_TYPE_DATA&&rsk->state==RUDP_STATE_ESTABLISHED)
	{
		if(ntohl(rh->seq)==rsk->last_ack+1||rsk->last_ack==0)
		{
			rsk->last_ack = ntohl(rh->seq);
			skb_pull(skb,sizeof(struct RUDP_header));
			rudp_send_ack(sk,ntohl(rh->seq));
			printk("a data packet comes!\n");
			return sock_queue_rcv_skb(sk, skb);
		}
		else
		{
			rudp_send_ack(sk,rsk->last_ack);
			return 0;
		}
	}
	else if(packet_type==RUDP_TYPE_SYN&&rsk->state==RUDP_STATE_LISTEN)
	{
		rudp_send_synack(sk,(struct sockaddr*)&addrin,skb);
		rsk->last_ack = ntohl(rh->seq);
		rsk->state = RUDP_STATE_SYN_RECV;
	}
	else if(packet_type==RUDP_TYPE_SYNACK)
	{
		unsigned int ackid = htonl(rh->ack),seqid = htonl(rh->seq);
		rudp_send_ack(sk,seqid);
		if(ackid==rsk->send_next_seq-1)
		{
			if(rsk->state==RUDP_STATE_SYN_SENT)
			{
				rsk->last_ack = ackid;
				rsk->state = RUDP_STATE_ESTABLISHED;
				printk("Client coonection established!\n");
			}	
		}
	}
	else if(packet_type==RUDP_TYPE_ACK&&rsk->state==RUDP_STATE_SYN_RECV)
	{
		printk("Server connection established!\n");
		rsk->state = RUDP_STATE_ESTABLISHED;
	}
	
	
	if(packet_type==RUDP_TYPE_ACK||packet_type==RUDP_TYPE_SYNACK)
	{
		printk(KERN_INFO "Received ack = %u!\n",ntohl(rh->ack));
		unsigned int ackid = ntohl(rh->ack);
		rudp_rcv_ack(sk,ackid);
		return 0;
	}

	return 0;
}

int rudp_send_ack(struct sock *sk, unsigned int ackid)
{
	// struct rudp_sock *rsk = rudp_sk(sk);
	struct sk_buff *skb;
	struct inet_sock *inet = inet_sk(sk);
	
	skb = rudp_ip_make_skb(sk,0);
	if(IS_ERR_OR_NULL(skb))
	{
		printk(KERN_INFO "fail to allocate skb!\n");
		return 0;
	}
	struct RUDP_header * rudphdr = rudp_hdr(skb);
	int offset = skb_transport_offset(skb);
	int len = skb->len - offset;

	struct udphdr *uh = udp_hdr(skb);
	uh->source = inet->inet_sport;
	uh->dest = inet->inet_dport;
	uh->len = htons(len);
	uh->check = 0;

	rudphdr->type = htons(RUDP_TYPE_ACK)>>8;
	rudphdr->seq = 0;
	rudphdr->ack = htonl(ackid);
	// printk(KERN_INFO "SYN seq=%u type=%x\n",rsk->send_next_seq-1,rudphdr->type);
	rudphdr->len = 0;
	
	ip_send_skb(sock_net(sk),skb);
	return 0;
}

int rudp_rcv_ack(struct sock *sk, unsigned int ackid)
{
	struct RUDP_header *rh;
	struct rudp_sock *rsock = rudp_sk(sk);

	bh_lock_sock(sk);

	struct sk_buff *pskb,*temp;
	bool isCleared = false;

	// remove packet whose ack==ackid from out_queue
	skb_queue_walk_safe(&rsock->out_queue,pskb,temp)
	{
		rh = rudp_hdr(pskb);
		if(ntohl(rh->seq)<=ackid)
		{
			printk(KERN_INFO "Remove ack=%u from queue\n",ntohl(rh->seq));
			skb_unlink(pskb,&rsock->out_queue);
			kfree_skb(pskb);
			rsock->in_flight--;
			// rsock->in_queue--;
			isCleared = true;
		}
	}

	// if there is a skb removed from out_queue, then try flush new packet from send_queue

	if(isCleared)
			try_flush_send_queue(sk);
	bh_unlock_sock(sk);	
	
	

	return -1;
}

// deprecated
int rudp_send_synack(struct sock *sk, struct sockaddr *uaddr,struct sk_buff *skb)
{
	struct RUDP_header *rh = rudp_hdr(skb);
	struct rudp_sock *rsk = rudp_sk(sk);
	struct sockaddr_in *usin = (struct sockaddr_in *)uaddr;
	struct inet_sock *inet = inet_sk(sk);

	rsk->last_ack = ntohl(rh->seq);
	struct sk_buff *newskb = rudp_ip_make_skb(sk,0);

	int offset = skb_transport_offset(newskb);
	int len = newskb->len - offset;

	struct RUDP_header *newrh = rudp_hdr(newskb);
	struct udphdr *uh = udp_hdr(newskb);
	// printk(KERN_INFO "transhdr = %d\n",newskb->transport_header);
	uh->source = inet->inet_sport;
	uh->dest = usin->sin_port;
	uh->len = htons(len);
	uh->check = 0;

	newrh->type = htons(RUDP_TYPE_SYNACK)>>8;
	newrh->seq = htonl(rsk->send_next_seq++);
	newrh->ack = htonl(rsk->last_ack++);
	newrh->len = 0;
	rudp_add_to_snd_queue(newskb);
	return 0;
}

int rudp_err(struct sk_buff *skb, u32 info)
{
    struct net_protocol *udp_protocol_ref = rcu_dereference(inet_protos[IPPROTO_UDP]);
    return udp_protocol_ref->err_handler(skb,info);
}

void win_inc(struct sock *sk)
{
	struct rudp_sock *rsk = rudp_sk(sk);
	if(rsk->win_size==1)
	{
		rsk->win_size = 16;
		return ;
	}

	if(rsk->win_size<=rsk->thresh)
		rsk->win_size *= 2;
	else
		rsk->win_size += 2;

	if(rsk->win_size>=64)
		rsk->win_size = 64;
}
void win_dec(struct sock *sk)
{
	struct rudp_sock *rsk = rudp_sk(sk);
	rsk->win_size = rsk->win_size*4/5;
	if(rsk->win_size<1)
		rsk->win_size = 1;
}