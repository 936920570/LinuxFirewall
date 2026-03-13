
#include "netlink_k.h"

static struct sock *nlsock = NULL;

int nl_send(unsigned int pid, void *data, unsigned int len) 
{
	int retval;
	struct nlmsghdr *nlh;
	struct sk_buff *skb;
	// init sk_buff
	skb = nlmsg_new(len, GFP_ATOMIC);
	if (skb == NULL) 
    {
		printk(KERN_WARNING "nl_send:alloc reply nlmsg skb failed!\n");
		return -1;
	}
	nlh = nlmsg_put(skb, 0, 0, 0, NLMSG_SPACE(len) - NLMSG_HDRLEN, 0);
	// send data
	memcpy(NLMSG_DATA(nlh), data, len);
    //NETLINK_CB(skb).portid = 0;
	NETLINK_CB(skb).dst_group = 0;
	retval = netlink_unicast(nlsock, skb, pid, MSG_DONTWAIT);
	printk("nl_send:send to user pid=%d,len=%d,ret=%d\n", pid, nlh->nlmsg_len - NLMSG_SPACE(0), retval);
	return retval;
}

void nl_recv(struct sk_buff *skb) 
{
	void *data;
	struct nlmsghdr *nlh = NULL;
	unsigned int pid,len;
    // check skb
    nlh = nlmsg_hdr(skb);
	if ((nlh->nlmsg_len < NLMSG_HDRLEN) || (skb->len < nlh->nlmsg_len)) {
		printk(KERN_WARNING "nl_recv: Illegal netlink packet!\n");
		return;
	}
    // deal data
	data = NLMSG_DATA(nlh);
    pid = nlh->nlmsg_pid;
    len = nlh->nlmsg_len - NLMSG_SPACE(0);
	if(len<sizeof(struct userRequest)) {
		printk(KERN_WARNING "nl_recv: packet size < userRequest!\n");
		return;
	}
	printk("nl_recv: data receive from user: user_pid=%d, len=%d\n", pid, len);
	processUserRequest(pid, data, len);
}

struct netlink_kernel_cfg nltest_cfg = 
{
	.groups = 0,
	.flags = 0,
	.input = nl_recv,
	.cb_mutex = NULL,
	.bind = NULL,
	.unbind = NULL,
	.compare = NULL,
};

void netlink_init(void) 
{
    nlsock = netlink_kernel_create(&init_net, NETLINK_MYFW, &nltest_cfg);
	if (!nlsock) 
    {
		printk(KERN_WARNING "netlink_init: create netlink socket failed\n");
		return;
	}
	printk("netlink_init: netlink_kernel_create() success, nlsock = %p\n", nlsock);
}

void netlink_release(void) 
{
    netlink_kernel_release(nlsock);
}