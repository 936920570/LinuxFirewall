#include "FWLogs.h"
static struct logItem *logHead = NULL,*logEnd = NULL;
static unsigned int logNum = 0;
static DEFINE_RWLOCK(logLock);
//保留最大数目的最新日志
int updateLog(void) 
{
    struct logItem *tmp;
    unsigned int count = 0;

    write_lock(&logLock);
    while(logNum > MAX_LOG_LEN) 
    {
        if(logHead == NULL) 
        { // 链表头指针丢失
            logHead = logEnd;
            logNum = logEnd==NULL ? 0 : 1;
            write_unlock(&logLock);
            return count;
        }
        tmp = logHead;
        logHead = logHead->next;
        logNum--;
        count++;
        if(logEnd == tmp) 
        { // 链表尾指针丢失
            logEnd = logHead;
            logNum = logEnd==NULL ? 0 : 1;
        }
        kfree(tmp);
    }
    write_unlock(&logLock);

    return count;
}

// 新增日志记录
int insertLog(struct logItem log)
{
    struct logItem *newLog;
    newLog = (struct logItem *) kzalloc(sizeof(struct logItem), GFP_KERNEL);
    if(newLog == NULL) 
    {
        printk(KERN_WARNING "insertLog: kzalloc failed.\n");
        return 0;
    }
    memcpy(newLog, &log, sizeof(struct logItem));
    newLog->next = NULL;
    // 新增日志至日志链表
    write_lock(&logLock);
    if(logEnd == NULL) 
    { // 日志链表为空
        logEnd = newLog;
        logHead = logEnd;
        logNum = 1;
        write_unlock(&logLock);
        return 1;
    }
    logEnd->next = newLog;
    logEnd = newLog;
    logNum++;
    write_unlock(&logLock);
    if(logNum > MAX_LOG_LEN) 
        updateLog();
    return 1;
}

int addLog(unsigned int action, struct sk_buff *skb) 
{
    struct logItem log;
    unsigned short sport=0,dport=0;
	struct iphdr *iph;
    struct timeval now = {
        .tv_sec = 0,
        .tv_usec = 0
    };
    do_gettimeofday(&now);
    log.time = now.tv_sec;
    iph = ip_hdr(skb);

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

    log.saddr = ntohl(iph->saddr);
    log.daddr = ntohl(iph->daddr);
    log.sport = sport;
    log.dport = dport;
    log.len = iph->tot_len - (iph->ihl * 4);
    log.protocol = iph->protocol;
    log.action = action;
    log.next = NULL;
    return insertLog(log);
}

// 将所有过滤日志形成Netlink回包
void* formAllLogItems(unsigned int num, unsigned int *len) {
    struct kernelAnswerHead *head;
    struct logItem *now;
    void *mem,*p;
    unsigned int count;
    read_lock(&logLock);
    for(now=logHead,count=0;now!=NULL;now=now->next,count++); // 计算日志总量
    printk("mod_FWLogs: form logs count=%d, need num=%d.\n", count, num);
    if(num == 0 || num > count)
        num = count;
    *len = sizeof(struct kernelAnswerHead) + sizeof(struct logItem) * num; // 申请回包空间
    mem = kzalloc(*len, GFP_ATOMIC);
    if(mem == NULL) 
    {
        printk(KERN_WARNING "mod_FWLogs: kzalloc failed.\n");
        read_unlock(&logLock);
        return NULL;
    }
    // 构建回包
    head = (struct kernelAnswerHead *)mem;
    head->type = RSP_Logs;
    head->arrayLen = num;
    p=(mem + sizeof(struct kernelAnswerHead));
    for(now=logHead;now!=NULL;now=now->next) 
    {
        if(count > num) 
        { // 只取最后num个日志
            count--;
            continue;
        }
        memcpy(p, now, sizeof(struct logItem));
        p=p+sizeof(struct logItem);
    }
    read_unlock(&logLock);
    return mem;
}