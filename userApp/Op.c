#include "structs.h"
#include "netlink_u.h"
int IPstr2IPint(const char *ipStr, unsigned int *ip, unsigned int *mask){
	// init
	int p = -1, count = 0;
	unsigned int len = 0, tmp = 0, r_mask = 0, r_ip = 0,i;
	for(i = 0; i < strlen(ipStr); i++){
		if(!(ipStr[i]>='0' && ipStr[i]<='9') && ipStr[i]!='.' && ipStr[i]!='/')
			return -1;
	}
	// 获取掩码
	for(i = 0; i < strlen(ipStr); i++)
        if(p != -1)
		{
            len *= 10;
            len += ipStr[i] - '0';
        }
        else if(ipStr[i] == '/')p = i;
	if(len > 32 || (p>=0 && p<7))
		return -1;

    if(p != -1)
        if(len)r_mask = 0xFFFFFFFF << (32 - len);
    else r_mask = 0xFFFFFFFF;//默认16
	// 获取IP
    for(i = 0; i < (p>=0 ? p : strlen(ipStr)); i++)
	{
        if(ipStr[i] == '.')
		{
            r_ip = r_ip | (tmp << (8 * (3 - count)));
            tmp = 0;
            count++;
            continue;
        }
        tmp *= 10;
        tmp += ipStr[i] - '0';
		if(tmp>256 || count>3)
			return -2;
    }
    r_ip = r_ip | tmp;
	
	*ip = r_ip;
	*mask = r_mask;
    return 0;
}

int IPint2IPstr(unsigned int ip, unsigned int mask, char *ipStr) {
    unsigned int i,ips[4],maskNum = 32;
    if(ipStr == NULL) {
        return -1;
    }
	if(mask == 0)
		maskNum = 0;
	else {
		while((mask & 1u) == 0) {
                	maskNum--;
                	mask >>= 1;
        	}
	}
    for(i=0;i<4;i++) {
        ips[i] = ((ip >> ((3-i)*8)) & 0xFFU);
    }
	sprintf(ipStr, "%u.%u.%u.%u/%u", ips[0], ips[1], ips[2], ips[3], maskNum);
	return 0;
}

int IPint2IPstrNoMask(unsigned int ip, char *ipStr) {
    unsigned int i,ips[4];
    if(ipStr == NULL) {
        return -1;
    }
    for(i=0;i<4;i++) {
        ips[i] = ((ip >> ((3-i)*8)) & 0xFFU);
    }
	sprintf(ipStr, "%u.%u.%u.%u", ips[0], ips[1], ips[2], ips[3]);
	return 0;
}

int IPint2IPstrWithPort(unsigned int ip, unsigned short port, char *ipStr) {
    if(port == 0) {
        return IPint2IPstrNoMask(ip, ipStr);
    }
    unsigned int i,ips[4];
    if(ipStr == NULL) {
        return -1;
    }
    for(i=0;i<4;i++) {
        ips[i] = ((ip >> ((3-i)*8)) & 0xFFU);
    }
	sprintf(ipStr, "%u.%u.%u.%u:%u", ips[0], ips[1], ips[2], ips[3], port);
	return 0;
}

struct kernelAnswer addFilterRule(char *after,char *name,char *sip,char *dip,unsigned int sport,unsigned int dport,u_int8_t proto,unsigned int log,unsigned int action) {
	struct userRequest req;
    struct kernelAnswer rsp;
	// form rule
	struct FWRule rule;
	if(IPstr2IPint(sip,&rule.saddr,&rule.smask)!=0) {
		rsp.code = ERROR_CODE_WRONG_IP;
		return rsp;
	}
	if(IPstr2IPint(dip,&rule.daddr,&rule.dmask)!=0) {
		rsp.code = ERROR_CODE_WRONG_IP;
		return rsp;
	}
	rule.saddr = rule.saddr;
	rule.daddr = rule.daddr;
	rule.sport = sport;
	rule.dport = dport;
	rule.log = log;
	rule.action = action;
	rule.protocol = proto;
	strncpy(rule.name, name, MAXRuleNameLen);
	// form req
	req.type = REQ_ADDIPRule;
	req.ruleName[0]=0;
	strncpy(req.ruleName, after, MAXRuleNameLen);
	req.message.rule = rule;
	// exchange
	return user2kernel(&req, sizeof(req));
}

struct kernelAnswer delFilterRule(char *name) {
	struct userRequest req;
	// form request
	req.type = REQ_DELIPRule;
	strncpy(req.ruleName, name, MAXRuleNameLen);
	// exchange
	return user2kernel(&req, sizeof(req));
}

struct kernelAnswer getAllFilterRules(void) {
	struct userRequest req;
	// exchange message
	req.type = REQ_GETAllIPRules;
	return user2kernel(&req, sizeof(req));
}

struct kernelAnswer addNATRule(char *sip,char *natIP,unsigned short minport,unsigned short maxport) {
	struct userRequest req;
	struct kernelAnswer rsp;
	// form rule
	struct NATRecord rule;
	if(IPstr2IPint(natIP,&rule.daddr,&rule.smask)!=0) {
		rsp.code = ERROR_CODE_WRONG_IP;
		return rsp;
	}
	if(IPstr2IPint(sip,&rule.saddr,&rule.smask)!=0) {
		rsp.code = ERROR_CODE_WRONG_IP;
		return rsp;
	}
	rule.sport = minport;
	rule.dport = maxport;
	// form req
	req.type = REQ_ADDNATRule;
	req.message.natRule = rule;
	// exchange
	return user2kernel(&req, sizeof(req));
}

struct kernelAnswer delNATRule(int num) {
	struct userRequest req;
	struct kernelAnswer rsp;
	if(num < 0) {
		rsp.code = ERROR_CODE_NO_SUCH_RULE;
		return rsp;
	}
	req.type = REQ_DELNATRule;
	req.message.count = num;
	// exchange
	return user2kernel(&req, sizeof(req));
}

struct kernelAnswer getAllNATRules(void) {
	struct userRequest req;
	// exchange message
	req.type = REQ_GETNATRules;
	return user2kernel(&req, sizeof(req));
}

struct kernelAnswer setDefaultAction(unsigned int action) {
	struct userRequest req;
	// form request
	req.type = REQ_SETAction;
	req.message.defaultAction = action;
	// exchange
	return user2kernel(&req, sizeof(req));
}

struct kernelAnswer getLogs(unsigned int num) {
	struct userRequest req;
	// exchange message
	req.message.count = num;
	req.type = REQ_GETAllIPLogs;
	return user2kernel(&req, sizeof(req));
}

struct kernelAnswer getAllConns(void) {
	struct userRequest req;
	// exchange message
	req.type = REQ_GETAllConns;
	return user2kernel(&req, sizeof(req));
}
