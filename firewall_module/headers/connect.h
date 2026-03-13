#include "linux.h"
#include "structs.h"
#include "myhash.h"

#include "nat.h"
#include "FWRules.h"

// 是否超时
bool checkTimer(unsigned long expires);

void addConnExpires(struct connectionNode *node, unsigned int plus);
// 检查是否存在指定连接
struct connectionNode *hasConn(unsigned int sip, unsigned int dip, unsigned short sport, unsigned short dport);

// 新建连接
struct connectionNode *addConn(unsigned int sip, unsigned int dip, unsigned short sport, unsigned short dport, u_int8_t proto, u_int8_t log);

// 设置连接的NAT
int setConnNAT(struct connectionNode *node, struct NATRule record, int natType);
// 依据过滤规则，删除相关连接
int eraseConnRelated(struct FWRule rule);

// 刷新连接池（定时器所用），删除超时连接
void updateConn(void);

// 初始化连接池相关内容（包括定时器）
void conn_init(void);
// 关闭连接池
void conn_exit(void);

// 将所有已有连接形成Netlink回包
void* formAllConns(unsigned int *len);
