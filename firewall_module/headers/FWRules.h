#include "linux.h"
#include "structs.h"

int eraseConnRelated(struct FWRule rule);
//检查单条规则是否匹配
bool getMatched(struct FWRule *rule,unsigned int srcIP, unsigned int destIP,
unsigned short sport, unsigned int dport, unsigned short proto); 
//匹配规则
bool matchFWRules(struct sk_buff *skb, struct FWRule *rule); 
//添加规则
struct FWRule * appendFWRules(char name[], struct FWRule rule); 
// 删除规则
int removeFWRules(char name[]); 
// 将所有规则形成Netlink回包
void* formAllFWRules(unsigned int *len);