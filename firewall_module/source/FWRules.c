#include "FWRules.h"

static struct FWRule *ruleHead= NULL;
DEFINE_RWLOCK(FWRuleLock);

//检查单条规则是否匹配
bool getMatched(struct FWRule *rule,unsigned int srcIP, unsigned int destIP,
unsigned short sport, unsigned int dport, unsigned short proto) 
{
    return (ipcmp(srcIP,rule->saddr,rule->smask) &&
			ipcmp(destIP,rule->daddr,rule->dmask) &&
			(sport >= ((unsigned short)(rule->sport >> 16)) && sport <= ((unsigned short)(rule->sport & 0xFFFFu))) &&
			(dport >= ((unsigned short)(rule->dport >> 16)) && dport <= ((unsigned short)(rule->dport & 0xFFFFu))) &&
			(rule->protocol == IPPROTO_IP || rule->protocol == proto));
}
//匹配规则
bool matchFWRules(struct sk_buff *skb, struct FWRule *rule) 
{
    bool match=false;
    struct FWRule *p;
	unsigned short sport=0,dport=0;
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

	read_lock(&FWRuleLock);
	for(p=ruleHead;p!=NULL;p=p->next) 
		if(getMatched(p,ntohl(iph->saddr),ntohl(iph->daddr),sport,dport,iph->protocol)) 
        {
            printk("match rule:%s",p->name);
            match=true;
			*rule=*p; 
            //printk("%p",rule);
			break;
		}
	read_unlock(&FWRuleLock);

	return match;
}

//添加规则
struct FWRule * appendFWRules(char name[], struct FWRule rule) 
{
    struct FWRule *p;
    struct FWRule *newFWRule = (struct FWRule *) kzalloc(sizeof(struct FWRule), GFP_KERNEL);
    if(newFWRule == NULL) 
    {
        printk(KERN_WARNING "appendFWRules: kzalloc failed.\n");
        return NULL;
    }
    memcpy(newFWRule, &rule, sizeof(struct FWRule));
    // 新增规则至规则链表
    write_lock(&FWRuleLock);
    // if(rule.action != NF_ACCEPT) 
    //     eraseConnRelated(rule); // 消除新增规则的影响
    if(ruleHead == NULL) 
    {
        ruleHead = newFWRule;
        ruleHead->next = NULL;
        write_unlock(&FWRuleLock);
        return newFWRule;
    }
    if(strlen(name)==0) 
    {
        newFWRule->next = ruleHead;
        ruleHead = newFWRule;
        write_unlock(&FWRuleLock);
        return newFWRule;
    }
    for(p=ruleHead;p!=NULL;p=p->next) 
        if(strcmp(p->name, name)==0) 
        {
            newFWRule->next = p->next;
            p->next = newFWRule;
            write_unlock(&FWRuleLock);
            return newFWRule;
        }
    write_unlock(&FWRuleLock);
    kfree(newFWRule);
    return NULL;
}

// 删除规则
int removeFWRules(char name[]) 
{
    struct FWRule *p,*pnext;
    int count = 0;
    write_lock(&FWRuleLock);
    while(ruleHead!=NULL && strcmp(ruleHead->name,name)==0) 
    {
        p = ruleHead;
        ruleHead = ruleHead->next;
        eraseConnRelated(*p); // 消除删除规则的影响
        kfree(p);
        count++;
    }
    for(p=ruleHead;p!=NULL && p->next!=NULL;p = p->next) 
        if(strcmp(p->next->name,name)==0) 
        { // 删除下条规则
            pnext = p->next;
            p->next = p->next->next;
            eraseConnRelated(*pnext); // 消除删除规则的影响
            kfree(pnext);
            count++;
        }   
    
    write_unlock(&FWRuleLock);
    return count;
}
// 将所有规则形成Netlink回包
void* formAllFWRules(unsigned int *len) 
{
    struct kernelAnswerHead *head;
    struct FWRule *r=ruleHead;
    void *mem,*p;
    int count=0;

    read_lock(&FWRuleLock);
    while(r)
    {
        r=r->next;
        count++;
    }
    *len = sizeof(struct kernelAnswerHead)+sizeof(struct FWRule)*count;
    mem = kzalloc(*len, GFP_ATOMIC);
    if(mem == NULL) 
    {
        printk(KERN_WARNING "mod_FWRules:kernel space allocate failed\n");
        read_unlock(&FWRuleLock);
        return NULL;
    }

    head = (struct kernelAnswerHead *)mem;
    head->type = RSP_FWRules;
    head->arrayLen = count;
    for(r=ruleHead,p=(mem + sizeof(struct kernelAnswerHead));r!=NULL;r=r->next,p=p+sizeof(struct FWRule))
        memcpy(p, r, sizeof(struct FWRule));

    read_unlock(&FWRuleLock);
    return mem;
}