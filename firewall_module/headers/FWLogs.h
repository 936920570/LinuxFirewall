#include "linux.h"
#include "structs.h"

//保留最大数目的最新日志
int updateLog(void);
// 新增日志记录
int insertLog(struct logItem log);

int addLog(unsigned int action, struct sk_buff *skb);
// 将所有过滤日志形成Netlink回包
void* formAllLogItems(unsigned int num, unsigned int *len);