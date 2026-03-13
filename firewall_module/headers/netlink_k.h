
#include "linux.h"
#include "structs.h"
// #include "FWRules.h"
//#include "FWLogs.h"
//#include "statefulInspection.h"
#include "userOp.h"
int nl_send(unsigned int pid, void *data, unsigned int len);

void nl_recv(struct sk_buff *skb); 

void netlink_init(void); 

void netlink_release(void);
