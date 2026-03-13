#include "linux.h"
#include "structs.h"

#include "nat.h"
#include "FWRules.h"
// 比较连接标识符
int connKeyCmp(conn_key_t l, conn_key_t r) ;
// 按标识符查找节点，无该节点返回则NULL
struct connectionNode *searchNode(struct rb_root *root, conn_key_t key) ;
// 插入新节点，返回节点
struct connectionNode *insertNode(struct rb_root *root, struct connectionNode *data);
// 删除节点
void eraseNode(struct rb_root *root, struct connectionNode *node);
// --- 业务相关 ---
// 是否超时
bool checkTimer(unsigned long expires);
void addConnExpires(struct connectionNode *node, unsigned int plus);
// 检查是否存在指定连接
struct connectionNode* hasConn(unsigned int sip, unsigned int dip, unsigned short sport, unsigned short dport);
// 新建连接
struct connectionNode* addConn(unsigned int sip, unsigned int dip, unsigned short sport, unsigned short dport, u_int8_t proto, u_int8_t log);
// 设置连接的NAT
int setConnNAT(struct connectionNode *node, struct NATRule record, int natType);
// 获取新的可用NAT端口
unsigned short getNewNATPort(struct NATRule rule);
// 将所有已有连接形成Netlink回包
void* formAllConns(unsigned int *len);
// 依据过滤规则，删除相关连接
int eraseConnRelated(struct FWRule rule);
// 刷新连接池（定时器所用），删除超时连接
int updateConn(void);
// 初始化连接池相关内容（包括定时器）
void conn_init(void);
// 关闭连接池
void conn_exit(void);
