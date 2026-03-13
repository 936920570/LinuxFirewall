#include "display.h"
#include "structs.h"

// 新增过滤规则时的用户交互
struct kernelAnswer cmdAddRule() {
	struct kernelAnswer empty;
	char after[MAXRuleNameLen+1],name[MAXRuleNameLen+1],saddr[25],daddr[25],sport[15],dport[15],protoS[6];
	unsigned short sportMin,sportMax,dportMin,dportMax;
	unsigned int action = NF_DROP, log = 0, proto, i;
	empty.code = ERROR_CODE_EXIT;
	// 前序规则名
	printf("Please input name of rule that you add rule after [default: head of link]: ");
	for(i=0;;i++) {
		if(i>MAXRuleNameLen) {
			printf("name length too long.\n");
			return empty;
		}
		after[i] = getchar();
		if(after[i] == '\n' || after[i] == '\r') {
			after[i] = '\0';
			break;
		}
	}
	// 规则名
	printf("Please input rule name (<%d and not null): ", MAXRuleNameLen);
	scanf("%s",name);
	if(strlen(name)==0 || strlen(name)>MAXRuleNameLen)
	{
		printf("name length between 1 and 11.\n");
		return empty;
	}
	// 源IP
	printf("Please input src ip (127.0.0.1/24): ");
	scanf("%s",saddr);
	// 源端口
	printf("Please input src port range(0-65535 or any): ");
	scanf("%s",sport);
	if(strcmp(sport, "any") == 0) {
		sportMin = 0,sportMax = 0xFFFFu;
	} else {
		sscanf(sport,"%hu-%hu",&sportMin,&sportMax);
	}
	if(sportMin > sportMax) {
		printf("min port > max port.\n");
		return empty;
	}
	// 目的IP
	printf("Please input dest ip(127.0.0.1/24): ");
	scanf("%s",daddr);
	// 目的端口
	printf("Please input dest port range(0-65535 or any): ");
	scanf("%s",dport);
	if(strcmp(dport, "any") == 0) {
		dportMin = 0,dportMax = 0xFFFFu;
	} else {
		sscanf(dport,"%hu-%hu",&dportMin,&dportMax);
	}
	if(dportMin > dportMax) {
		printf("min port > max port.\n");
		return empty;
	}
	// 协议
	printf("Please input protocol(TCP/UDP/ICMP/any): ");
	scanf("%s",protoS);
	if(strcmp(protoS,"TCP")==0)
		proto = IPPROTO_TCP;
	else if(strcmp(protoS,"UDP")==0)
		proto = IPPROTO_UDP;
	else if(strcmp(protoS,"ICMP")==0)
		proto = IPPROTO_ICMP;
	else if(strcmp(protoS,"any")==0)
		proto = IPPROTO_IP;
	else {
		printf("This protocol Please input is not supported.\n");
		return empty;
	}
	// 动作
	printf("action (Please input 1/0 for accept/drop): ");
	scanf("%d",&action);
	// 是否记录日志
	printf("log? (Please input 1/0 for yes/no): ");
	scanf("%u",&log);
	printf("Results:\n");
	return addFilterRule(after,name,saddr,daddr,
		(((unsigned int)sportMin << 16) | (((unsigned int)sportMax) & 0xFFFFu)),
		(((unsigned int)dportMin << 16) | (((unsigned int)dportMax) & 0xFFFFu)),proto,log,action);
}

void wrongCommand() {
	printf("illegal command format.\n");
	printf("myFW <cmd type> <action> [sup args]\n");
	printf("commands:\n");
	printf("rule <add | del | show | default> [del rule's name]\n");
	printf("nat  <add | del | show> [del number]\n");
	printf("show <rule | nat | log | connect>\n");
	exit(0);
}

struct kernelAnswer cmdAddNATRule()
{
	struct kernelAnswer empty;
	char saddr[25],daddr[25],port[15];
	unsigned short portMin,portMax;
	empty.code = ERROR_CODE_EXIT;
	printf("ONLY source NAT is supported\n");
	// 源IP
	printf("Please input src ip (127.0.0.1/24): ");
	scanf("%s",saddr);
	// NAT IP
	printf("Please input NAT ip(192.168.52.1): ");
	scanf("%s",daddr);
	// 目的端口
	printf("Please input NAT port range(0-65535 or any): ");
	scanf("%s",port);
	if(strcmp(port, "any") == 0)
		portMin = 0,portMax = 0xFFFFu;
	else sscanf(port,"%hu-%hu",&portMin,&portMax);

	if(portMin > portMax) 
	{
		printf("min port > max port.\n");
		return empty;
	}
	return addNATRule(saddr,daddr,portMin,portMax);
}

int main(int argc, char *argv[]) 
{
	if(argc<3) 
    {
		//addRule("","rj","192.168.80.138","47.100.10.21",-1,-1,IPPROTO_ICMP,1,NF_DROP);
		//addNATRule("192.168.60.2", "192.168.80.139",20000,35535);
		wrongCommand();
		return 0;
	}
	struct kernelAnswer rsp;
	rsp.code = ERROR_CODE_EXIT;
	// 过滤规则相关
	if(strcmp(argv[1], "rule")==0 || argv[1][0] == 'r') {
		if(strcmp(argv[2], "show")==0 || strcmp(argv[2], "list")==0) {
		// 列出所有过滤规则
			rsp = getAllFilterRules();
		} else if(strcmp(argv[2], "del")==0) {
		// 删除过滤规则
			if(argc < 4)
				printf("Please point rule name in option.\n");
			else if(strlen(argv[3])>MAXRuleNameLen)
				printf("rule name too long!");
			else
				rsp = delFilterRule(argv[3]);
		} else if(strcmp(argv[2], "add")==0) {
		// 添加过滤规则
			rsp = cmdAddRule();
		} else if(strcmp(argv[2], "default")==0) {
		// 设置默认规则
			if(argc < 4)
				printf("Please point default action in option.\n");
			else if(strcmp(argv[3], "accept")==0)
				rsp = setDefaultAction(NF_ACCEPT);
			else if(strcmp(argv[3], "drop")==0)
				rsp = setDefaultAction(NF_DROP);
			else
				printf("No such action. Only \"accept\" or \"drop\".\n");
		} else 
			wrongCommand();
	} else if(strcmp(argv[1], "nat")==0 || argv[1][0] == 'n') {
		if(strcmp(argv[2], "show")==0 || strcmp(argv[2], "show")==0) {
		// 列出所有NAT规则
			rsp = getAllNATRules();
		} else if(strcmp(argv[2], "del")==0) {
		// 删除NAT规则
			if(argc < 4)
				printf("Please point rule number(seq) in option.\n");
			else {
				int num;
				sscanf(argv[3], "%d", &num);
				rsp = delNATRule(num);
			}
		} else if(strcmp(argv[2], "add")==0) {
		// 添加NAT规则
			rsp = cmdAddNATRule();
		} else {
			wrongCommand();
		}
	} else if(strcmp(argv[1], "show")==0 || argv[1][0] == 'l') {
	// 展示相关
		if(strcmp(argv[2],"log")==0 || argv[2][0] == 'l') {
		// 过滤日志
			unsigned int num = 0;
			if(argc > 3)
				sscanf(argv[3], "%u", &num);
			rsp = getLogs(num);
		} else if(strcmp(argv[2],"connection")==0 || argv[2][0] == 'c') {
		// 连接状态
			rsp = getAllConns();
		} else if(strcmp(argv[2],"rule")==0 || argv[2][0] == 'r') {
		// 已有过滤规则
			rsp = getAllFilterRules();
		} else if(strcmp(argv[2],"nat")==0 || argv[2][0] == 'n') {
		// 已有NAT规则
			rsp = getAllNATRules();
		} else
			wrongCommand();
	} else 
		wrongCommand();
	processKernelAnswer(rsp);
}
