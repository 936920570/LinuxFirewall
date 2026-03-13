#include "hook.h"
#include "netlink_k.h"

unsigned int DEFAULT_ACTION = NF_ACCEPT;
bool ipcmp(unsigned int ipa, unsigned int ipb, unsigned int mask) 
{
    if((ipa & mask) == (ipb & mask))return true;
	else return false;
}

unsigned int hook_main(void *priv,struct sk_buff *skb,const struct nf_hook_state *state) 
{
    struct FWRule *rule=NULL;
    struct connectionNode *conn;
    unsigned short sport=0, dport=0;//默认为0
    unsigned int srcIP, destIP;
    unsigned int action=DEFAULT_ACTION;
    bool match = 0, isLog = 0;
    // 初始化
	struct iphdr *iph = ip_hdr(skb);
	if(iph->protocol==IPPROTO_TCP)
	{
        struct tcphdr *tcph=(struct tcphdr *)(skb->data + (iph->ihl * 4));
		sport = ntohs(tcph->source);dport = ntohs(tcph->dest);
    }
    else if(iph->protocol==IPPROTO_UDP)
    {
        struct udphdr *udph=(struct udphdr *)(skb->data + (iph->ihl * 4));
		sport = ntohs(udph->source);dport = ntohs(udph->dest);
    }

    srcIP = ntohl(iph->saddr);
    destIP = ntohl(iph->daddr);
    //查询是否有已有连接
    conn = hasConn(srcIP, destIP, sport, dport);
    if(conn != NULL) 
    {
        if(conn->needLog)addLog(action, skb);//记录日志
        return NF_ACCEPT;
    }
    printk("a packect not in connections\n");
    //匹配规则
    match = matchFWRules(skb, rule);
    // if(rule==NULL)printk("rule==NULL");
    // if(match==0)printk("match=0");
    if(match&&rule) 
    { //成功匹配
        printk("Match rule:%s.\n", rule->name);
        if(rule->action==NF_ACCEPT)action =NF_ACCEPT;
        else action =NF_DROP;
        if(rule->log) 
        { // 记录日志
            isLog = 1;
            addLog(action, skb);//添加日志
        }
    }
    //更新连接池
    if(action == NF_ACCEPT)addConn(srcIP,destIP,sport,dport,iph->protocol,isLog);

    return action;
}

unsigned int hook_nat_in(void *priv,struct sk_buff *skb,const struct nf_hook_state *state) {
    struct connectionNode *conn;
    struct NATRule record;
    unsigned short sport=0, dport=0;
    unsigned int sip, dip;
    u_int8_t proto;
    struct tcphdr *tcph;
    struct udphdr *udph;
    int hdr_len, tot_len;
    // 初始化
    struct iphdr *iph = ip_hdr(skb);
    if(iph->protocol==IPPROTO_TCP)
	{
        struct tcphdr *tcph=(struct tcphdr *)(skb->data + (iph->ihl * 4));
		sport = ntohs(tcph->source);dport = ntohs(tcph->dest);
    }
    else if(iph->protocol==IPPROTO_UDP)
    {
        struct udphdr *udph=(struct udphdr *)(skb->data + (iph->ihl * 4));
		sport = ntohs(udph->source);dport = ntohs(udph->dest);
    }

    sip = ntohl(iph->saddr);
    dip = ntohl(iph->daddr);
    proto = iph->protocol;
    // 查连接池 NAT_TYPE_DEST
    conn = hasConn(sip, dip, sport, dport);
    if(conn == NULL) { // 不应出现连接表中不存在的情况
        printk(KERN_WARNING "hook_nat_in:get a connection that is not in the connection pool!\n");
        return NF_ACCEPT;
    }
    // 无记录->返回
    if(conn->natType != NAT_TYPE_DEST)
        return NF_ACCEPT;

    // 转换目的地址+端口
    record = conn->nat;
    iph->daddr = htonl(record.daddr);
    hdr_len = iph->ihl * 4;
    tot_len = ntohs(iph->tot_len);
    iph->check = 0;
    iph->check = ip_fast_csum(iph, iph->ihl);
    switch(proto) {
        case IPPROTO_TCP:
            tcph = (struct tcphdr *)(skb->data + (iph->ihl * 4));
            tcph->dest = htons(record.dport);
            tcph->check = 0;
            skb->csum = csum_partial((unsigned char *)tcph, tot_len - hdr_len, 0);
            tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
                                        tot_len - hdr_len, iph->protocol, skb->csum);
            break;
        case IPPROTO_UDP:
            udph = (struct udphdr *)(skb->data + (iph->ihl * 4));
            udph->dest = htons(record.dport);
            udph->check = 0;
            skb->csum = csum_partial((unsigned char *)udph, tot_len - hdr_len, 0);
            udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
                                        tot_len - hdr_len, iph->protocol, skb->csum);
            break;
        case IPPROTO_ICMP:
        default:break;
    }
    return NF_ACCEPT;
}