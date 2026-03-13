#include "structs.h"


void printLine(int len);

int showOneRule(struct FWRule rule);



int showRules(struct FWRule *rules, int len);


int showNATRules(struct NATRecord *rules, int len);


int showOneLog(struct logItem log);


int showLogs(struct logItem *logs, int len);


int showOneConn(struct ConnLog log);

int showConns(struct ConnLog *logs, int len);

void processKernelAnswer(struct kernelAnswer rsp);
