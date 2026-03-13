
#ifndef _STRUCTS_H_
#define _STRUCTS_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/netfilter.h>
#include <linux/netlink.h>

// ---- APP 与 Kernel 通用协议 ------
#define MAXRuleNameLen 11

#define REQ_GETAllIPRules 1
#define REQ_ADDIPRule 2
#define REQ_DELIPRule 3
#define REQ_SETAction 4 
#define REQ_GETAllIPLogs 5
#define REQ_GETAllConns 6
#define REQ_ADDNATRule 7
#define REQ_DELNATRule 8
#define REQ_GETNATRules 9

#define RSP_Only_Head 10
#define RSP_MSG 11
#define RSP_IPRules 12  // body为IPRule[]
#define RSP_IPLogs 13   // body为IPlog[]
#define RSP_NATRules 14 // body为NATRecord[]
#define RSP_ConnLogs 15 // body为ConnLog[]

struct FWRule
{
    char name[MAXRuleNameLen+1];
    unsigned int saddr;
    unsigned int smask;
    unsigned int daddr;
    unsigned int dmask;
    unsigned int sport; // 源端口范围 高2字节为最小 低2字节为最大
    unsigned int dport; // 目的端口范围 同上
    u_int8_t protocol;
    unsigned int action;
    unsigned int log;
    struct FWRule* next;
};

struct logItem 
{
    long tm;
    unsigned int saddr;
    unsigned int daddr;
    unsigned short sport;
    unsigned short dport;
    u_int8_t protocol;
    unsigned int len;
    unsigned int action;
    struct logItem* next;
};

struct NATRecord
{ 
    unsigned int saddr; 
    unsigned short sport; 
    unsigned int daddr; 
    unsigned short dport;

    unsigned int smask; 
    unsigned short nowPort; 
    struct NATRecord* next;
};

struct ConnLog
{
    unsigned int saddr;
    unsigned int daddr;
    unsigned short sport;
    unsigned short dport;
    u_int8_t protocol;
    int natType;
    struct NATRecord nat; // NAT记录
};

struct userRequest
{
    unsigned int type;//用户请求操作类型（操作码）
    char ruleName[MAXRuleNameLen+1];//规则名称
    union
    {
        struct FWRule rule;//过滤规则
        struct NATRecord natRule;//NAT规则
        unsigned int defaultAction;//默认规则
        unsigned int count;//序号
    } message;
};



#define NAT_TYPE_NO 0
#define NAT_TYPE_SRC 1
#define NAT_TYPE_DEST 2

// ----- 上层应用专用 ------
#define uint8_t unsigned char
#define NETLINK_MYFW 17
#define MAX_PAYLOAD (1024 * 256)

#define ERROR_CODE_EXIT -1
#define ERROR_CODE_EXCHANGE -2 // 与内核交换信息失败
#define ERROR_CODE_WRONG_IP -11 // 错误的IP格式
#define ERROR_CODE_NO_SUCH_RULE -12

/** 
 * @brief 内核回应包
 */
struct kernelAnswerHead
{
    unsigned int type;//回应操作码
    unsigned int arrayLen;//数据数组长度
};
struct kernelAnswer
{
    int code; //内核回应操作码
    void *data; //内核回应的数据
    struct kernelAnswerHead *header; //指向data中的头部
    void *body; //指向data中的Body
};

/**
 * @brief 与内核交换数据
 * @param smsg: 发送的消息
 * @param slen: 发送消息的长度
 * @return kernelAnswer: 接收到的回应，其中data字段记得free
 */
struct kernelAnswer exchangeMsgK(void *smsg, unsigned int slen);

// ----- 与内核交互函数 -----

struct kernelAnswer addFilterRule(char *after,char *name,char *sip,char *dip,unsigned int sport,unsigned int dport,u_int8_t proto,unsigned int log,unsigned int action); // 新增一条过滤规则，其中，sport/dport为端口范围：高2字节为最小 低2字节为最大
struct kernelAnswer delFilterRule(char *name);
struct kernelAnswer getAllFilterRules(void);
struct kernelAnswer addNATRule(char *sip,char *natIP,unsigned short minport,unsigned short maxport);
struct kernelAnswer delNATRule(int num);
struct kernelAnswer getAllNATRules(void);
struct kernelAnswer setDefaultAction(unsigned int action);
struct kernelAnswer getLogs(unsigned int num); // num=0时，获取所有日志
struct kernelAnswer getAllConns(void);

// ----- 一些工具函数 ------

int IPstr2IPint(const char *ipStr, unsigned int *ip, unsigned int *mask);
int IPint2IPstr(unsigned int ip, unsigned int mask, char *ipStr);
int IPint2IPstrNoMask(unsigned int ip, char *ipStr);
int IPint2IPstrWithPort(unsigned int ip, unsigned short port, char *ipStr);

#endif