
#include "linux.h"
#include "structs.h"
struct myhashindex * createindex(struct connectionNode *conn);

struct myhashtable *myhash_create(void);

void myhash_add(struct myhashtable *table,struct connectionNode *conn);

void myhash_del(struct myhashtable *table,struct connectionNode *conn);

bool _myhash_match(struct myhashtable *table,struct connectionNode *conn,bool reverse);

bool myhash_match(struct myhashtable *table,struct connectionNode *conn);

struct connectionNode *myhash_find(struct myhashtable *table,unsigned int key[3]);

void myhash_clean(struct myhashtable *table);

void myhash_clear(struct myhashtable *table);
