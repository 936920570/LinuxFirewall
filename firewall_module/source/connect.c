#include "connect.h"

static DEFINE_RWLOCK(connLock);
static struct myhashtable *ctable = NULL;

// 是否超时
bool checkTimer(unsigned long expires)
{
	return (jiffies >= expires)? 1: 0;  // 当前时间 >= 超时时间 ?
}
void addConnExpires(struct connectionNode *node, unsigned int plus)
{
	if(node == NULL)return;
	write_lock(&connLock);
	node->expires = timeFromNow(plus);
	write_unlock(&connLock);
}
// 检查是否存在指定连接
struct connectionNode *hasConn(unsigned int sip, unsigned int dip, unsigned short sport, unsigned short dport)
{
	unsigned int key[3];
	struct connectionNode *node = NULL;
	// 构建标识符
	key[0] = sip;
	key[1] = dip;
	key[2] = ((((unsigned int)sport) << 16) | ((unsigned int)dport));
	// 查找节点
	read_lock(&connLock);
	node=myhash_find(ctable,key);
	// if(node)printk("node is not null\n");
	// else printk("node is null\n");
	read_unlock(&connLock);
	addConnExpires(node, CONN_EXPIRES); // 重新设置超时时间
	return node;
}

// 新建连接
struct connectionNode *addConn(unsigned int sip, unsigned int dip, unsigned short sport, unsigned short dport, u_int8_t proto, u_int8_t log)
{// 初始化
	struct connectionNode *node=NULL;
	node = (struct connectionNode *)kzalloc(sizeof(struct connectionNode), GFP_ATOMIC);
	if(node == NULL) 
	{
		printk(KERN_WARNING "mod_statefulInspection:addConn: kzalloc failed.\n");
		return NULL;
	}
	node->needLog = log;
	node->protocol = proto;
	node->expires = timeFromNow(CONN_EXPIRES); // 设置超时时间
	node->natType = NAT_TYPE_NO;
	// 构建标识符
	node->key[0] = sip;
	node->key[1] = dip;
	node->key[2] = ((((unsigned int)sport) << 16) | ((unsigned int)dport));
	write_lock(&connLock);
	myhash_add(ctable,node);
	write_unlock(&connLock);
	return node;
}

// 设置连接的NAT
int setConnNAT(struct connectionNode *node, struct NATRule record, int natType)
{
	if(node==NULL)
		return 0;
	write_lock(&connLock);
	node->natType = natType;
	node->nat = record;
	write_unlock(&connLock);
	return 1;
}


// 依据过滤规则，删除相关连接
int eraseConnRelated(struct FWRule rule)
{
	struct connectionNode *tmp;
	unsigned short sport,dport;
	unsigned int count = 0,hashv;
	// 初始化
	rule.protocol = IPPROTO_IP;
	// 删除相关节点
	write_lock(&connLock);
	for (hashv=0; hashv < HASH_SIZE(ctable->hashtable); hashv++)
    hlist_for_each_entry(tmp, &(ctable->hashtable)[hashv], node)
	{ // 有更改时，持续遍历，防止漏下节点
		sport = (unsigned short)(tmp->key[2] >> 16);
		dport = (unsigned short)(tmp->key[2] & 0xFFFFu);
		if(getMatched(&rule, tmp->key[0], tmp->key[1], sport, dport, tmp->protocol))
		{ // 相关规则
			myhash_del(ctable, tmp);
			count++;
		}
	}
	write_unlock(&connLock);
	printk("mod_statefulInspection: erase all related conn finish.\n");
	return count;
}

// 刷新连接池（定时器所用），删除超时连接
void updateConn(void) 
{
	struct connectionNode *tmp;
	unsigned int hashv;
	write_lock(&connLock);
	for (hashv=0; hashv < HASH_SIZE(ctable->hashtable); hashv++)
    	hlist_for_each_entry(tmp, &(ctable->hashtable)[hashv], node)
		{
			if(checkTimer(tmp->expires))
				myhash_del(ctable, tmp);
		}
	write_unlock(&connLock);
}
// --- 定时器相关 ---
static struct timer_list conn_timer;//定义计时器

// 计时器回调函数
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
void conn_timer_callback(unsigned long arg) {
#else
void conn_timer_callback(struct timer_list *t) {
#endif
    updateConn();
	mod_timer(&conn_timer, timeFromNow(CONN_ROLL_INTERVAL)); //重新激活定时器
}
// 初始化连接池相关内容（包括定时器）
void conn_init(void) 
{
	ctable=myhash_create();
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
    init_timer(&conn_timer);
    conn_timer.function = &conn_timer_callback;//设置定时器回调方法
    conn_timer.data = ((unsigned long)0);
#else
    timer_setup(&conn_timer, conn_timer_callback, 0);
#endif
	conn_timer.expires = timeFromNow(CONN_ROLL_INTERVAL);//超时时间设置为CONN_ROLL_INTERVAL秒后
	add_timer(&conn_timer);//激活定时器
}

// 关闭连接池
void conn_exit(void) 
{
	del_timer(&conn_timer);
}

// 将所有已有连接形成Netlink回包
void* formAllConns(unsigned int *len)
{
    struct kernelAnswerHead *head;
    struct connectionNode *tmp;
	struct ConnLog log;
    void *mem,*p;
    unsigned int count=ctable->count,hashv;
    read_lock(&connLock);
	// 申请回包空间
	*len = sizeof(struct kernelAnswerHead) + sizeof(struct ConnLog) * count;
	mem = kzalloc(*len, GFP_ATOMIC);
    if(mem == NULL)
	{
        printk(KERN_WARNING "mod_statefulInspection: kzalloc failed.\n");
        read_unlock(&connLock);
        return NULL;
    }
    // 构建回包
    head = (struct kernelAnswerHead *)mem;
    head->type = RSP_ConnLogs;
    head->arrayLen = count;
    p=(mem + sizeof(struct kernelAnswerHead));
    for (hashv=0; hashv < HASH_SIZE(ctable->hashtable); hashv++)
        hlist_for_each_entry(tmp, &(ctable->hashtable)[hashv], node)
	{
		log.saddr = tmp->key[0];
		log.daddr = tmp->key[1];
		log.sport = (unsigned short)(tmp->key[2] >> 16);
		log.dport = (unsigned short)(tmp->key[2] & 0xFFFFu);
		log.protocol = tmp->protocol;
		log.natType = tmp->natType;
		log.nat = tmp->nat;
		memcpy(p, &log, sizeof(struct ConnLog));
		p+=sizeof(struct ConnLog);
	}
    read_unlock(&connLock);
    return mem;
}

// char *myhash_read(struct myhashtable *table, int *len)
// {
//     char *buff                    = NULL;
//     int i                         = 0;
//     int hashv                     = 0;
//     struct connectionNode *conn = NULL;
//     __be32 conn_num               = htonl(table->conn_num);

//     *len = sizeof(unsigned int) + sizeof(struct xwall_rule) * table->conn_num;
//     buff = (char *)kvzalloc(*len, GFP_KERNEL);
//     if (!buff)
//         return NULL;

//     read_lock(&table->lock);
//     memcpy(buff, &conn_num, sizeof(unsigned int));
//     for (hashv=0; hashv < HASH_SIZE(ctable->hashtable); hashv++)
//         hlist_for_each_entry(tmp, &(table->hashtable)[hashv], node)
//         {
//             memcpy(buff + sizeof(unsigned int) +
//                        sizeof(struct connectionNode) * i,
//                    tmp, sizeof(struct connectionNode));
//             i++;
//         }
//     read_unlock(&table->lock);

//     return buff;
// }