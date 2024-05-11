#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/export-internal.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

#ifdef CONFIG_UNWINDER_ORC
#include <asm/orc_header.h>
ORC_HEADER;
#endif

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x4d230517, "sock_queue_rcv_skb_reason" },
	{ 0xaf94ee80, "__ip_make_skb" },
	{ 0x88db9f48, "__check_object_size" },
	{ 0x9ebbc43, "udp_sk_rx_dst_set" },
	{ 0xf1c7abdf, "_copy_to_iter" },
	{ 0x38559747, "inet_unregister_protosw" },
	{ 0x1f4839b1, "skb_put" },
	{ 0x8d522714, "__rcu_read_lock" },
	{ 0x8ec760b0, "cgroup_bpf_enabled_key" },
	{ 0x7ba0c0ac, "skb_consume_udp" },
	{ 0x17b2cb4c, "inet_register_protosw" },
	{ 0xd11c28a6, "pcpu_hot" },
	{ 0x4afb2238, "add_wait_queue" },
	{ 0xb27c059b, "inet_protos" },
	{ 0x160f4037, "__skb_recv_udp" },
	{ 0xf6ebc03b, "net_ratelimit" },
	{ 0x26e7be43, "ip_route_output_flow" },
	{ 0xba8fbd64, "_raw_spin_lock" },
	{ 0xcbd4898c, "fortify_panic" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x65487097, "__x86_indirect_thunk_rax" },
	{ 0x122c3a7e, "_printk" },
	{ 0x18ba3fb1, "proto_unregister" },
	{ 0x392267aa, "__sock_recv_cmsgs" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x296695f, "refcount_warn_saturate" },
	{ 0x410d568d, "ip_setup_cork" },
	{ 0x2fe02517, "sk_reset_timer" },
	{ 0x216899cd, "inet_dgram_ops" },
	{ 0x22f160d8, "proto_register" },
	{ 0xd0654aba, "woken_wake_function" },
	{ 0xfd89cf7b, "skb_queue_tail" },
	{ 0x33338211, "rcuref_get_slowpath" },
	{ 0x1bdfe8c5, "sk_dst_check" },
	{ 0x2b743c2a, "skb_pull" },
	{ 0x2469810f, "__rcu_read_unlock" },
	{ 0x3ed753e7, "udp_prot" },
	{ 0xa9f5305f, "inet_add_protocol" },
	{ 0x7f6b2cde, "sk_free" },
	{ 0xa84891c5, "kfree_skb_reason" },
	{ 0xb29c751e, "dev_get_by_index_rcu" },
	{ 0xe8954570, "ip_send_skb" },
	{ 0x8a04acb1, "lock_sock_nested" },
	{ 0x3c3fce39, "__local_bh_enable_ip" },
	{ 0x4c83cd6a, "security_sk_classify_flow" },
	{ 0xe505ebe8, "skb_copy_datagram_iter" },
	{ 0xdccc6868, "l3mdev_master_ifindex_rcu" },
	{ 0x645175ba, "ip4_datagram_connect" },
	{ 0xcd67f708, "skb_queue_purge" },
	{ 0x5d496d49, "ip_make_skb" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x17fdbb68, "__pskb_pull_tail" },
	{ 0xa24c72c, "ip_generic_getfrag" },
	{ 0xcca9ad62, "skb_unlink" },
	{ 0x15ba50a6, "jiffies" },
	{ 0xccc683ef, "__udp4_lib_lookup" },
	{ 0x1cd0ed6e, "sk_stop_timer_sync" },
	{ 0xa648e561, "__ubsan_handle_shift_out_of_bounds" },
	{ 0xce79ae51, "inet_del_protocol" },
	{ 0xc6f46339, "init_timer_key" },
	{ 0x944f0160, "__cgroup_bpf_run_filter_sock_addr" },
	{ 0x452362fd, "sock_alloc_send_pskb" },
	{ 0x2cf56265, "__dynamic_pr_debug" },
	{ 0x4de2cabc, "sock_pfree" },
	{ 0x82c63603, "skb_clone" },
	{ 0x66d3a2e1, "dst_release" },
	{ 0xb308c97d, "wait_woken" },
	{ 0x37110088, "remove_wait_queue" },
	{ 0x4055a336, "__ip_flush_pending_frames" },
	{ 0x41ed3709, "get_random_bytes" },
	{ 0x54b1fac6, "__ubsan_handle_load_invalid_value" },
	{ 0xa2aeec52, "iov_iter_revert" },
	{ 0xb5b54b34, "_raw_spin_unlock" },
	{ 0x82de7197, "pskb_trim_rcsum_slow" },
	{ 0xe1d7bc5e, "release_sock" },
	{ 0x9ffbb7a5, "module_layout" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "D66C3676F041F3C22829061");
