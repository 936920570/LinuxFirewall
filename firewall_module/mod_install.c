#include "linux.h"
#include "hook.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anonymous");

static struct nf_hook_ops nfop_in={
	.hook = hook_main,
	.pf = PF_INET,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_FIRST//min
};

static struct nf_hook_ops nfop_out={
	.hook = hook_main,
	.pf = PF_INET,
	.hooknum = NF_INET_POST_ROUTING,
	.priority = NF_IP_PRI_FIRST//min
};

static struct nf_hook_ops natop_in={
	.hook = hook_nat_in,
	.pf = PF_INET,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_NAT_DST//-100
};


static int mod_init(void){
	printk("My Firewall module loaded. :)\n"); 
	nf_register_net_hook(&init_net,&nfop_in);
	nf_register_net_hook(&init_net,&nfop_out);
	nf_register_net_hook(&init_net,&natop_in);
	//nf_register_net_hook(&init_net,&natop_out);
	netlink_init();
	conn_init();
	return 0;
}

static void mod_exit(void){
	printk("My Firewall module unloaded.Bye~\n");
	nf_unregister_net_hook(&init_net,&nfop_in);
	nf_unregister_net_hook(&init_net,&nfop_out);
	nf_unregister_net_hook(&init_net,&natop_in);
	//nf_unregister_net_hook(&init_net,&natop_out);
	netlink_release();
	conn_exit();
}

module_init(mod_init);
module_exit(mod_exit);
