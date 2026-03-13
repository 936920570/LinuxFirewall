#include"myhash.h"
struct myhashindex * createindex(struct connectionNode *conn)
{
    struct myhashindex *idx = kzalloc(sizeof(*idx), GFP_KERNEL);
    if (!idx)
    {
        printk("createindex:create hash index failed!");
        return NULL;
    }
    idx->saddr    = conn->key[0];
    idx->daddr    = conn->key[1];
    //idx->protocol = conn->protocol;
    idx->sport          = conn->key[2]>>16;
    idx->dport          = (conn->key[2])&(0xffffu);
    return idx;
}
struct myhashtable *myhash_create()
{
    struct myhashtable *table = kzalloc(sizeof(*table), GFP_KERNEL);
    if (!table)return NULL;
    hash_init(table->hashtable);
    //rwlock_init(&table->lock);
    return table;
}

void myhash_add(struct myhashtable *table,struct connectionNode *conn)
{
    struct myhashindex *idx=createindex(conn);
    unsigned int hashv;
    myhash_JEN(idx, 12, hashv, HASH_BITS(table->hashtable));
    //printk("myhash:add hashv %d\n",hashv);
    table->count++;
    /* Use default hash functoin, need the sizeof(idx) <= 8. */
    // u64 idx_64 = *((u64 *)(&idx));
    // hash_add(table->hashtable, &conn->node, idx_64);

    /* Use custom hash function (Jenkins), need the sizeof(idx) == 12n. */
    hlist_add_head(&conn->node, &(table->hashtable)[hashv]);
}

void myhash_del(struct myhashtable *table,struct connectionNode *conn)
{
    table->count--;
    hash_del(&conn->node);
    kfree(conn);
}

struct connectionNode *myhash_find(struct myhashtable *table,unsigned int key[3])
{
	unsigned int hashv,i=0;
    struct myhashindex *idx;
    struct connectionNode *tmp,*conn,*result=NULL;
    conn = (struct connectionNode *)kzalloc(sizeof(struct connectionNode), GFP_ATOMIC);
    if(!conn)
    {
        printk("myhashfind: create connectionNode failed.\n");
        return NULL;
    }
    for(i=0;i<3;i++)conn->key[i] = key[i];
    
    idx=createindex(conn);
    myhash_JEN(idx, 12, hashv, HASH_BITS(table->hashtable));
	//read_lock(&connLock);
    hlist_for_each_entry(tmp, &(table->hashtable)[hashv], node)
	{
        printk("myhash:find hashv %d\n",hashv);
        for(i=0;i<3;i++)
            if(tmp->key[i]!=key[i])
                break;
        if(i==3)result=tmp;
    }
	//read_unlock(&connLock);
	return result;
}

void myhash_clear(struct myhashtable *table)
{
    unsigned int i;
    struct hlist_node *tmp        = NULL;
    struct connectionNode *conn = NULL;

    //write_lock(&table->lock);
    table->count = 0;
    for (i = 0; i < HASH_SIZE(table->hashtable); ++i)
        hlist_for_each_entry_safe(conn, tmp, &(table->hashtable)[i], node)
        {
            myhash_del(table,conn);
        }
    hash_init(table->hashtable);
    //write_unlock(&table->lock);
}


// bool _myhash_match(struct myhashtable *table,struct connectionNode *conn,bool reverse)
// {
//     unsigned int hashv;
//     bool res = false;
//     struct connectionNode *cur_conn;
//     struct myhashindex *idx=createindex(conn);
//     if (reverse) {
//         swap(idx->saddr, idx->daddr);
//         swap(idx->sport, idx->dport);
//         swap(conn->saddr, conn->daddr);
//     }
//     myhash_JEN(idx, sizeof(idx), hashv, HASH_BITS(table->hashtable));

//     //read_lock(&table->lock);
//     hlist_for_each_entry(cur_conn, &(table->hashtable)[hashv], node)
//     {
//         if (conn->protocol == IPPROTO_TCP)
//             if (reverse)
//                 swap(conn->tcp.sport, conn->tcp.dport);
//             res = existing_connection_tcp(cur_conn, conn);
//             if (reverse)swap(conn->tcp.sport, conn->tcp.dport);
//         else if (conn->protocol == IPPROTO_UDP)
//         {
//             if (reverse)
//                 swap(conn->udp.sport, conn->udp.dport);
//             res = (cur_conn->saddr == conn->saddr &&
//                    cur_conn->daddr == conn->daddr &&
//                    cur_conn->udp.sport == conn->udp.sport &&
//                    cur_conn->udp.dport == conn->udp.dport);
//             if (reverse)swap(conn->udp.sport, conn->udp.dport);
//         } 
//         else if (conn->protocol == IPPROTO_ICMP)
//         {
//             if (reverse) 
//                 res = cur_conn->saddr == conn->saddr &&
//                       cur_conn->daddr == conn->daddr &&
//                       cur_conn->icmp.type == ICMP_ECHO &&
//                       cur_conn->icmp.code == 0 &&
//                       conn->icmp.type == ICMP_ECHOREPLY && conn->icmp.code == 0;
//             else
//                 res = cur_conn->saddr == conn->saddr &&
//                       cur_conn->daddr == conn->daddr &&
//                       cur_conn->icmp.type == ICMP_ECHO &&
//                       cur_conn->icmp.code == 0 &&
//                       conn->icmp.type == ICMP_ECHO && conn->icmp.code == 0;
//         }
//         else res = existing_connection_others(cur_conn, conn);
//         if (res) {
//             if (ktime_cur_before((ktime_t)ntohll(cur_conn->timeout))) {
//                 switch (cur_conn->protocol) {
//                 case IPPROTO_ICMP:
//                     cur_conn->timeout = htonll(
//                         ktime_add_sec(ktime_get_real(), default_timeout_icmp));
//                     break;
//                 case IPPROTO_UDP:
//                     cur_conn->timeout = htonll(
//                         ktime_add_sec(ktime_get_real(), default_timeout_udp));
//                     break;
//                 case IPPROTO_TCP:
//                     cur_conn->timeout = htonll(
//                         ktime_add_sec(ktime_get_real(), default_timeout_tcp));
//                     break;
//                 default:
//                     cur_conn->timeout = htonll(ktime_add_sec(
//                         ktime_get_real(), default_timeout_others));
//                 }
//                 break;
//             } else res = false;
            
//         }
//     }
//     //read_unlock(&table->lock);

//     if (reverse)
//     {
//         swap(idx->saddr, idx->daddr);
//         swap(idx->sport, idx->dport);
//         swap(conn->saddr, conn->daddr);
//     }

//     return res;
// }

// bool myhash_match(struct myhashtable *table,struct connectionNode *conn)
// {
//     bool res = false;
//     struct myhashindex *idx=createindex(conn);
//     if (conn->protocol == IPPROTO_TCP)
//         res = _myhash_match(table, conn, idx, false) || _myhash_match(table, conn, idx, true);
//     else if (conn->protocol == IPPROTO_UDP)
//         res = _myhash_match(table, conn, idx, false) || _myhash_match(table, conn, idx, true);
//     else if (conn->protocol == IPPROTO_ICMP)
//         res = _myhash_match(table, conn, idx, false) || _myhash_match(table, conn, idx, true);
//     else res = _myhash_match(table, conn, idx, true);

//     return res;
// }