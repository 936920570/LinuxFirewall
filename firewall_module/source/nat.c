#include "nat.h"

static struct NATRule *natRuleHead = NULL;
static DEFINE_RWLOCK(natRuleLock);
// 首部新增一条NAT规则
struct NATRule * addNATRule(struct NATRule rule) 
{
    struct NATRule *newRule;
    newRule = (struct NATRule *) kzalloc(sizeof(struct NATRule), GFP_KERNEL);
    if(newRule == NULL) {
        printk(KERN_WARNING "mod_nat: kzalloc failed.\n");
        return NULL;
    }
    memcpy(newRule, &rule, sizeof(struct NATRule));
    // 新增规则至首部
    write_lock(&natRuleLock);
    newRule->next = natRuleHead;
    natRuleHead = newRule;
    write_unlock(&natRuleLock);
    return newRule;
}
// 删除序号为num的NAT规则
int deleteNATRule(int num) 
{
    struct NATRule *p,*tmp;
    struct FWRule rule;
    int count = 0;
    write_lock(&natRuleLock);
    if(num == 0) {
        tmp = natRuleHead;
        natRuleHead = natRuleHead->next;
        kfree(tmp);
        write_unlock(&natRuleLock);
        return 1;
    }
    for(p=natRuleHead,count=1;p!=NULL && p->next!=NULL;p=p->next,count++) 
        if(count == num) 
        { // 删除规则
            tmp = p->next;
            p->next = p->next->next;
            rule.saddr = tmp->saddr; // 消除连接池影响
            rule.smask = tmp->smask;
            rule.dmask = 0;
            rule.sport = 0xFFFFu;
            rule.dport = 0xFFFFu;
            eraseConnRelated(rule);
            kfree(tmp);
            write_unlock(&natRuleLock);
            return 1;
        }
    write_unlock(&natRuleLock);
    return 0;
}
bool matchNATRule(unsigned int saddr, unsigned int daddr, struct NATRule *rule) 
{
    struct NATRule *p;
    rule=NULL;
    read_lock(&natRuleLock);
	for(p=natRuleHead;p!=NULL;p=p->next) 
		if(ipcmp(saddr, p->saddr, p->smask) &&!ipcmp(daddr, p->saddr, p->smask) &&daddr != p->daddr)
        {
            read_unlock(&natRuleLock);
            rule=p;
			return true;
		}
	read_unlock(&natRuleLock);
    return false;
}
struct NATRule genNATRule(unsigned int preIP, unsigned int afterIP, unsigned short prePort, unsigned short afterPort)
{
    struct NATRule rule;
    rule.saddr = preIP;
    rule.sport = prePort;
    rule.daddr = afterIP;
    rule.dport = afterPort;
    return rule;
}
// 将所有NAT规则形成Netlink回包
void* formAllNATRules(unsigned int *len)
{
    struct kernelAnswerHead *head;
    struct NATRule *pnat;
    void *mem,*p;
    unsigned int count;
    read_lock(&natRuleLock);
    for(pnat=natRuleHead,count=0;pnat!=NULL;pnat=pnat->next,count++);
    *len = sizeof(struct kernelAnswerHead) + sizeof(struct NATRule)*count;
    mem = kzalloc(*len, GFP_ATOMIC);
    if(mem == NULL)
    {
        printk(KERN_WARNING "mod_nat:kzalloc failed.\n");
        read_unlock(&natRuleLock);
        return NULL;
    }
    head = (struct kernelAnswerHead *)mem;
    head->type = RSP_NATRules;
    head->arrayLen = count;
    for(pnat=natRuleHead,p=(mem + sizeof(struct kernelAnswerHead));pnat!=NULL;pnat=pnat->next,p=p+sizeof(struct NATRule))
        memcpy(p, pnat, sizeof(struct NATRule));
    read_unlock(&natRuleLock);
    return mem;
}