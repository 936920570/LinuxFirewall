
#include "linux.h"
#include "structs.h"
//#include "FWRules.h"
#include "FWLogs.h"
//#include "statefulInspection.h"
#include "connect.h"

int nl_send(unsigned int pid, void *data, unsigned int len);
int kernel2user(unsigned int pid, const char *msg);
void dealWithSetAction(unsigned int action);
int processUserRequest(unsigned int pid, void *msg, unsigned int len);