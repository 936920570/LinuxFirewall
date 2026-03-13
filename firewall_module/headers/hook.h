#include "linux.h"
#include "structs.h"
// unsigned int DEFAULT_ACTION = NF_ACCEPT;
// 初始化连接池相关内容（包括定时器）
void conn_init(void);
// 关闭连接池
void conn_exit(void);
void netlink_init(void); 
void netlink_release(void);
bool ipcmp(unsigned int ipa, unsigned int ipb, unsigned int mask);

unsigned int hook_main(void *priv,struct sk_buff *skb,const struct nf_hook_state *state); 
unsigned int hook_nat_in(void *priv,struct sk_buff *skb,const struct nf_hook_state *state);
unsigned int hook_nat_out(void *priv,struct sk_buff *skb,const struct nf_hook_state *state);
   