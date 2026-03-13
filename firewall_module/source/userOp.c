
#include "userOp.h"

extern unsigned int DEFAULT_ACTION;

int kernel2user(unsigned int pid, const char *msg) {
    void* mem;
    unsigned int rspLen;
    struct kernelAnswerHead *rspH;
    rspLen = sizeof(struct kernelAnswerHead) + strlen(msg) + 1;

    mem = kzalloc(rspLen, GFP_ATOMIC);
    if(mem == NULL) {
        printk(KERN_WARNING "mod_userOp: kernel2user kzalloc failed.\n");
        return 0;
    }
    rspH = (struct kernelAnswerHead *)mem;
    rspH->type = RSP_MSG;
    rspH->arrayLen = strlen(msg);
    memcpy(mem+sizeof(struct kernelAnswerHead), msg, strlen(msg));
    nl_send(pid, mem, rspLen);
    kfree(mem);
    return rspLen;
}

void dealWithSetAction(unsigned int action) {
    if(action != NF_ACCEPT) 
    {
        struct FWRule rule = 
        {
            .smask = 0,
            .dmask = 0,
            .sport = -1,
            .dport = -1
        }; // 清除全部连接
        eraseConnRelated(rule);
    }
}

int processUserRequest(unsigned int pid, void *msg, unsigned int len) {
    struct userRequest *op;
    struct kernelAnswerHead *rspH;
    void* mem;
    unsigned int rspLen = 0;
    op = (struct userRequest *) msg;
    switch (op->type)
    {
    case REQ_GETAllLogs:
        mem = formAllLogItems(op->message.count, &rspLen);
        if(mem == NULL) {
            printk(KERN_WARNING "processUserRequest: formAllLogs failed.\n");
            kernel2user(pid, "form logs failed.");
            break;
        }
        nl_send(pid, mem, rspLen);
        kfree(mem);
        break;
    case REQ_GETAllConns:
        mem = formAllConns(&rspLen);
        if(mem == NULL) {
            printk(KERN_WARNING "processUserRequest:formAllConns failed.\n");
            kernel2user(pid, "form connections failed.");
            break;
        }
        nl_send(pid, mem, rspLen);
        kfree(mem);
        break;
    case REQ_GETAllFWRules:
        mem = formAllFWRules(&rspLen);
        if(mem == NULL) {
            printk(KERN_WARNING "processUserRequest:formAllFWRules failed.\n");
            kernel2user(pid, "form rules failed.");
            break;
        }
        nl_send(pid, mem, rspLen);
        kfree(mem);
        break;
    case REQ_ADDFWRule:
        if(appendFWRules(op->ruleName, op->message.rule)==NULL) {
            rspLen = kernel2user(pid, "failed: no such rule or retry it.");
            printk("processUserRequest: add rule failed.\n");
        } else {
            rspLen = kernel2user(pid, "Success.");
            printk("processUserRequest: add rule : %s.\n", op->message.rule.name);
        }
        break;
    case REQ_DELFWRule:
        rspLen = sizeof(struct kernelAnswerHead);
        rspH = (struct kernelAnswerHead *)kzalloc(rspLen, GFP_KERNEL);
        if(rspH == NULL) {
            printk(KERN_WARNING "processUserRequest: deal kzalloc failed.\n");
            kernel2user(pid, "form rsp failed but delete maybe success.");
            break;
        }
        rspH->type = RSP_Only_Head;
        rspH->arrayLen = removeFWRules(op->ruleName);
        printk("processUserRequest: delete %d rules.\n", rspH->arrayLen);
        nl_send(pid, rspH, rspLen);
        kfree(rspH);
        break;
    case REQ_GETNATRules:
        mem = formAllNATRules(&rspLen);
        if(mem == NULL) {
            printk(KERN_WARNING "processUserRequest: formAllNATRules failed.\n");
            kernel2user(pid, "form NAT rules failed.");
            break;
        }
        nl_send(pid, mem, rspLen);
        kfree(mem);
        break;
    case REQ_ADDNATRule:
        if(addNATRule(op->message.natRule)==NULL) {
            rspLen = kernel2user(pid, "failed: please retry it.");
            printk("processUserRequest: add NAT rule failed.\n");
        } else {
            rspLen = kernel2user(pid, "Success.");
            printk("processUserRequest: add NAT rule .\n");
        }
        break;
    case REQ_DELNATRule:
        rspLen = sizeof(struct kernelAnswerHead);
        rspH = (struct kernelAnswerHead *)kzalloc(rspLen, GFP_KERNEL);
        if(rspH == NULL) {
            printk(KERN_WARNING "processUserRequest: kzalloc failed.\n");
            kernel2user(pid, "form rsp failed but delete maybe success.");
            break;
        }
        rspH->type = RSP_Only_Head;
        rspH->arrayLen = deleteNATRule(op->message.count);
        printk("processUserRequest: del %d NAT rules.\n", rspH->arrayLen);
        nl_send(pid, rspH, rspLen);
        kfree(rspH);
        break;
    case REQ_SETAction:
        if(op->message.defaultAction == NF_ACCEPT) {
            DEFAULT_ACTION = NF_ACCEPT;
            rspLen = kernel2user(pid, "Set default action: ACCEPT.");
            printk("processUserRequest: Set default action: ACCEPT.\n");
        } else {
            DEFAULT_ACTION = NF_DROP;
            rspLen = kernel2user(pid, "Set default action: DROP.");
            printk("processUserRequest: Set default action: DROP.\n");
        }
        dealWithSetAction(DEFAULT_ACTION);
        break;
    default:
        rspLen = kernel2user(pid, "No such operation.");
        break;
    }
    return rspLen;
}