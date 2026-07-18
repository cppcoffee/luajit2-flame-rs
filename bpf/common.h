#ifndef __COMMON_H
#define __COMMON_H

#define TASK_COMM_LEN                  16
#define MAX_ENTRIES                    10240
#define CHUNKNAME_LEN                  128
#define MAX_LUA_DEPTH                  8
#define PERF_MAX_STACK_DEPTH           32
#define USER_STACK_SNAPSHOT_SIZE       4096
#define USER_STACK_SNAPSHOT_CHUNK_SIZE 512

enum func_type {
    FUNC_TYPE_LUA = 0,
    FUNC_TYPE_C = 1,
    FUNC_TYPE_F = 2,
    FUNC_TYPE_JIT = 3,
};

struct sample_key {
    unsigned int pid;
    unsigned int tid;
    unsigned int seq; /* per-tid sample sequence */
};

/* Native stack input. bpf_get_stack fills `ips` leaf-first; registers and
 * stack bytes are used for user-space DWARF unwinding. */
struct native_event {
    struct sample_key key; /* correlates with lua_stack_event.key */
    unsigned int ip_cnt;
    unsigned int stack_len;
    unsigned long long ip;
    unsigned long long sp;
    unsigned long long fp;
    unsigned long long lr;
    unsigned long long ips[PERF_MAX_STACK_DEPTH];
    unsigned char stack[USER_STACK_SNAPSHOT_SIZE];
};

/* one walked LuaJIT frame. */
struct lua_stack_event {
    struct sample_key key;    /* same key as the native sample */
    int level;                /* 0 = topmost */
    int type;                 /* enum func_type */
    char name[CHUNKNAME_LEN]; /* chunkname, e.g. "@foo.lua" */
    unsigned long long funcp; /* C function address (FUNC_TYPE_C) */
    int line;                 /* source line (LUA) or ffid (F) */
};

#endif /* __COMMON_H */
