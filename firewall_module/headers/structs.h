#include "linux.h"
#ifndef _STRUCTS_H_
#define _STRUCTS_H_
//#include"uthash.h"
// netlink 协议号
#define NETLINK_MYFW 17

#define RSP_Logs 13
#define MAX_LOG_LEN 100
#define MaxNameLen 50
#define RSP_FWRules 12 


#define MAXRuleNameLen 11

#define REQ_GETAllFWRules 1
#define REQ_ADDFWRule 2
#define REQ_DELFWRule 3
#define REQ_SETAction 4 
#define REQ_GETAllLogs 5
#define REQ_GETAllConns 6
#define REQ_ADDNATRule 7
#define REQ_DELNATRule 8
#define REQ_GETNATRules 9

#define RSP_Only_Head 10
#define RSP_MSG 11
#define RSP_FWRules 12 
#define RSP_Logs 13 
#define RSP_NATRules 14 
#define RSP_ConnLogs 15 

struct FWRule
{//防火墙规则
    char name[MAXRuleNameLen+1];//防火墙名称
    struct FWRule* next;//下一条过滤规则

    unsigned int saddr;//源IP
    unsigned int smask;//源IP掩码长度
    unsigned int sport;//源端口
    unsigned int daddr;//目的IP
    unsigned int dmask;//目的IP掩码长度
    unsigned int dport;//目的端口
    u_int8_t protocol;//协议号

    unsigned int action;//对应的处理动作
    unsigned int log;//是否记录日志
};

struct logItem 
{
    long time;//日志时间
    unsigned int saddr;//源IP
    unsigned short sport;//源端口
    unsigned int daddr;//目的IP
    unsigned short dport;//目的端口
    u_int8_t protocol;//协议号
    unsigned int len;//日志长度
    unsigned int action;//日志处理动作
    struct logItem* next;//下一条日志
};
struct kernelAnswerHead
{
    unsigned int type;//内核应答对应的操作码
    unsigned int arrayLen;//数据数组长度
};

struct NATRule 
{ 
    unsigned int saddr;//原始IP
    unsigned int smask;//IP掩码长度
    unsigned short sport;//原始端口

    unsigned int daddr;//转换后IP
    unsigned short dport;//转换后端口
    unsigned short nowPort;//当前使用端口
    struct NATRule* next;//下一条NAT规则
};

struct ConnLog 
{
    unsigned int saddr;
    unsigned int daddr;
    unsigned short sport;
    unsigned short dport;
    u_int8_t protocol;
    int natType;
    struct NATRule nat; 
};

struct userRequest 
{
    unsigned int type;
    char ruleName[MAXRuleNameLen+1];
    union 
    {
        struct FWRule rule;
        struct NATRule natRule;
        unsigned int defaultAction;
        unsigned int count;
    } message;
};

#define NAT_TYPE_NO 0
#define NAT_TYPE_SRC 1
#define NAT_TYPE_DEST 2


#define CONN_NEEDLOG 0x10
#define CONN_EXPIRES 10 // 新建连接或已有连接刷新时的存活时长（秒）
#define CONN_NAT_TIMES 10 // NAT的超时时间倍率
#define CONN_ROLL_INTERVAL 5 // 定期清理超时连接的时间间隔（秒）



#include <linux/hashtable.h>
#include <linux/list.h>
#define hashtable_size 16
#define HASH_JEN_MIX(a,b,c)                                                      \
do {                                                                             \
  a -= b; a -= c; a ^= ( c >> 13 );                                              \
  b -= c; b -= a; b ^= ( a << 8 );                                               \
  c -= a; c -= b; c ^= ( b >> 13 );                                              \
  a -= b; a -= c; a ^= ( c >> 12 );                                              \
  b -= c; b -= a; b ^= ( a << 16 );                                              \
  c -= a; c -= b; c ^= ( b >> 5 );                                               \
  a -= b; a -= c; a ^= ( c >> 3 );                                               \
  b -= c; b -= a; b ^= ( a << 10 );                                              \
  c -= a; c -= b; c ^= ( b >> 15 );                                              \
} while (0)

#define HASH_JEN(key,keylen,hashv)                                               \
do {                                                                             \
  unsigned _hj_i,_hj_j,_hj_k;                                                    \
  unsigned const char *_hj_key=(unsigned const char*)(key);                      \
  hashv = 0xfeedbeefu;                                                           \
  _hj_i = _hj_j = 0x9e3779b9u;                                                   \
  _hj_k = (unsigned)(keylen);                                                    \
  while (_hj_k >= 12U) {                                                         \
    _hj_i +=    (_hj_key[0] + ( (unsigned)_hj_key[1] << 8 )                      \
        + ( (unsigned)_hj_key[2] << 16 )                                         \
        + ( (unsigned)_hj_key[3] << 24 ) );                                      \
    _hj_j +=    (_hj_key[4] + ( (unsigned)_hj_key[5] << 8 )                      \
        + ( (unsigned)_hj_key[6] << 16 )                                         \
        + ( (unsigned)_hj_key[7] << 24 ) );                                      \
    hashv += (_hj_key[8] + ( (unsigned)_hj_key[9] << 8 )                         \
        + ( (unsigned)_hj_key[10] << 16 )                                        \
        + ( (unsigned)_hj_key[11] << 24 ) );                                     \
                                                                                 \
     HASH_JEN_MIX(_hj_i, _hj_j, hashv);                                          \
                                                                                 \
     _hj_key += 12;                                                              \
     _hj_k -= 12U;                                                               \
  }                                                                              \
  hashv += (unsigned)(keylen);                                                   \
  switch ( _hj_k ) {                                                             \
    case 11: hashv += ( (unsigned)_hj_key[10] << 24 ); /* FALLTHROUGH */         \
    case 10: hashv += ( (unsigned)_hj_key[9] << 16 );  /* FALLTHROUGH */         \
    case 9:  hashv += ( (unsigned)_hj_key[8] << 8 );   /* FALLTHROUGH */         \
    case 8:  _hj_j += ( (unsigned)_hj_key[7] << 24 );  /* FALLTHROUGH */         \
    case 7:  _hj_j += ( (unsigned)_hj_key[6] << 16 );  /* FALLTHROUGH */         \
    case 6:  _hj_j += ( (unsigned)_hj_key[5] << 8 );   /* FALLTHROUGH */         \
    case 5:  _hj_j += _hj_key[4];                      /* FALLTHROUGH */         \
    case 4:  _hj_i += ( (unsigned)_hj_key[3] << 24 );  /* FALLTHROUGH */         \
    case 3:  _hj_i += ( (unsigned)_hj_key[2] << 16 );  /* FALLTHROUGH */         \
    case 2:  _hj_i += ( (unsigned)_hj_key[1] << 8 );   /* FALLTHROUGH */         \
    case 1:  _hj_i += _hj_key[0];                      /* FALLTHROUGH */         \
    default: ;                                                                   \
  }                                                                              \
  HASH_JEN_MIX(_hj_i, _hj_j, hashv);                                             \
} while (0)

#define myhash_JEN(keyptr, keylen, hashv, bits)                            \
    do {                                                                       \
        HASH_JEN(keyptr, keylen, hashv);                                       \
        hashv >>= (32 - bits);                                                 \
    } while (0)

struct myhashindex
{
    unsigned int saddr;//源IP
    unsigned int daddr;//目的IP
    unsigned short sport;//源端口
    unsigned short dport;//目的端口
    u_int8_t protocol;//协议号
};
struct myhashtable 
{
    unsigned int count;//当前连接数
    struct hlist_head hashtable[1 << (hashtable_size)];//连接表头指针
};

typedef unsigned int conn_key_t[3]; // 连接标识符，用于标明一个连接，可比较

struct connectionNode 
{
    unsigned int key[3]; // 连接标识符
    unsigned long expires; //超时时间=当前时间jiffies+时间限制
    u_int8_t protocol; // 协议号
    u_int8_t needLog; // 是否记录日志

    struct NATRule nat;//该连接对应的NAT规则（如果有）
    int natType;   // NAT转换类型，未用到

    struct hlist_node node;//hash表节点
};

// struct mynode
// {
//     unsigned int key[3]; // 整数数组作为键
// 	struct connectionNode c;
// 	UT_hash_handle hh; // Uthash 的哈希表句柄
// };

#define timeFromNow(plus) (jiffies + ((plus) * HZ))

bool ipcmp(unsigned int ipl, unsigned int ipr, unsigned int mask);

#endif

