#include "linux.h"
#include "structs.h"

int eraseConnRelated(struct FWRule rule);
// 首部新增一条NAT规则
struct NATRule * addNATRule(struct NATRule rule);
// 删除序号为num的NAT规则
int deleteNATRule(int num);
// 将所有NAT规则形成Netlink回包
void* formAllNATRules(unsigned int *len);

bool matchNATRule(unsigned int saddr, unsigned int daddr, struct NATRule *rule);

struct NATRule genNATRule(unsigned int preIP, unsigned int afterIP, unsigned short prePort, unsigned short afterPort);
