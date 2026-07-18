#ifndef __LUA_STATE_H
#define __LUA_STATE_H

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

/* =========================================================================
 *  LuaJIT internal data structures, ported for eBPF user-space probing.
 *  Compile-time switch:  -DLJ_TARGET_GC64=0   for 32-bit non-GC64 builds.
 *  x86-64 LuaJIT (OpenResty default) uses GC64.
 * ========================================================================= */
#ifndef LJ_TARGET_GC64
#define LJ_TARGET_GC64 1
#endif

#define LJ_GC64 (LJ_TARGET_GC64)
#define LJ_FR2  (LJ_GC64) /* 64-bit GC needs two-slot frames */

/* read a field of a user-space struct into a stack-local of an explicit
 * type. We rely on compile-time field offset calculation (the struct
 * layout is fixed and matches the target LuaJIT build), NOT on CO-RE
 * relocation — CO-RE only works for kernel BTF types, and our lua_State /
 * GCproto are user-defined types that have no matching kernel BTF. */
#define LUARD_T(src, field, type)                                              \
    ({                                                                         \
        type _v;                                                               \
        __builtin_memset(&_v, 0, sizeof(_v));                                  \
        bpf_probe_read_user(&_v, sizeof(_v), (const void *)&(src)->field);     \
        _v;                                                                    \
    })

/* read into a caller-provided buffer */
#define LUARD(dst, src, field)                                                 \
    bpf_probe_read_user(dst, sizeof(*(dst)), (const void *)&(src)->field)

/* ---- scalar typedefs -------------------------------------------------- */
typedef uint32_t MSize;
typedef uint64_t GCSize;
typedef uint8_t BCOp;
typedef uint32_t BCIns;
typedef uint32_t BCPos;
typedef uint32_t BCReg;
typedef int32_t BCLine;
typedef double lua_Number;
typedef int (*lua_CFunction)(void *L);

/* ---- references ------------------------------------------------------- */
typedef struct GCRef {
#if LJ_GC64
    uint64_t gcptr64;
#else
    uint32_t gcptr32;
#endif
} GCRef;

typedef struct MRef {
#if LJ_GC64
    uint64_t ptr64;
#else
    uint32_t ptr32;
#endif
} MRef;

#if LJ_GC64
#define mrefu64(r)  ((uint64_t)(r).ptr64)
#define gcrefu64(r) ((uint64_t)(r).gcptr64)
#else
#define mrefu64(r)  ((uint64_t)(uint32_t)(r).ptr32)
#define gcrefu64(r) ((uint64_t)(uint32_t)(r).gcptr32)
#endif

#define LJ_GCVMASK (((uint64_t)1 << 47) - 1)

/* Generated from the supported OpenResty LuaJIT2 GC64 ABI. These user-space
 * types cannot use kernel CO-RE relocation. */
#define LJ_G_OFS_CUR_L    376
#define LJ_G_OFS_JIT_BASE 384

/* ---- tagged value (8 bytes) ------------------------------------------- *
 * We only need two interpretations in the BPF probe:
 *   .gcr  (a GCobj reference, possibly with tag bits)
 *   .ftsz (frame type+size or PC, used as int64)
 */
typedef union TValue {
    uint64_t u64;
    GCRef gcr;
    int64_t ftsz;
} TValue;

typedef const TValue cTValue;

/* ---- object tags ------------------------------------------------------ */
#define LJ_TFUNC      (~8u)
#define LJ_GCT_THREAD 6
#define LJ_GCT_FUNC   8

/* ---- GC header / string ----------------------------------------------- */
#define GCHeader                                                               \
    GCRef nextgc;                                                              \
    uint8_t marked;                                                            \
    uint8_t gct

typedef struct GCstr {
    GCHeader;
    uint8_t reserved;
    uint8_t hashalg;
    uint32_t sid;
    uint32_t hash;
    MSize len;
} GCstr;

#define strdata(s) ((const char *)((s) + 1))

/* ---- prototype -------------------------------------------------------- */
typedef struct GCproto {
    GCHeader;
    uint8_t numparams;
    uint8_t framesize;
    MSize sizebc;
#if LJ_GC64
    uint32_t unused_gc64;
#endif
    GCRef gclist;
    MRef k;
    MRef uv;
    MSize sizekgc;
    MSize sizekn;
    MSize sizept;
    uint8_t sizeuv;
    uint8_t flags;
    uint16_t trace;
    /* debug-only fields: */
    GCRef chunkname;
    BCLine firstline;
    BCLine numline;
    MRef lineinfo;
    MRef uvinfo;
    MRef varinfo;
} GCproto;

#define proto_bc(pt)        ((BCIns *)((char *)(pt) + sizeof(GCproto)))
#define proto_bcpos(pt, pc) ((BCPos)((pc) - proto_bc(pt)))

/* ---- frame type markers ----------------------------------------------- */
enum {
    FRAME_LUA,
    FRAME_C,
    FRAME_CONT,
    FRAME_VARG,
    FRAME_LUAP,
    FRAME_CP,
    FRAME_PCALL,
    FRAME_PCALLH
};
#define FRAME_TYPE  3
#define FRAME_P     4
#define FRAME_TYPEP (FRAME_TYPE | FRAME_P)

/* read the ftsz slot of a frame slot. In FR2, LuaJIT's `frame' pointer is the
 * PC/delta/ftsz slot; the function GC reference is in frame[-1]. */
#if LJ_FR2
static __always_inline ptrdiff_t frame_ftsz(cTValue *f)
{
    /* FR2 layout: frame points to the "func" slot; the ftsz/PC is in
     * frame[+1] (i.e. the slot right above func). */
    return (ptrdiff_t)LUARD_T(f, ftsz, int64_t);
}
static __always_inline const BCIns *frame_pc(cTValue *f)
{
    uint64_t v = (uint64_t)LUARD_T(f, ftsz, int64_t);
    return (const BCIns *)v;
}
#else
static __always_inline ptrdiff_t frame_ftsz(cTValue *f)
{
    /* non-FR2: a TValue's high 32 bits hold the tag/ftsz via fr.tp.ftsz.
     * On LE that's the second 32-bit word of the 8-byte TValue. */
    uint32_t v = 0;
    bpf_probe_read_user(&v, sizeof(v), (const void *)&f->u64 + 4);
    return (ptrdiff_t)(int32_t)v;
}
static __always_inline const BCIns *frame_pc(cTValue *f)
{
    uint64_t v = 0;
    bpf_probe_read_user(&v, sizeof(v), (const void *)&f->u64 + 4);
    return (const BCIns *)v;
}
#endif

static __always_inline int frame_type(cTValue *f)
{
    return frame_ftsz(f) & FRAME_TYPE;
}
static __always_inline int frame_typep(cTValue *f)
{
    return frame_ftsz(f) & FRAME_TYPEP;
}
static __always_inline bool frame_islua(cTValue *f)
{
    return frame_type(f) == FRAME_LUA;
}
static __always_inline bool frame_isvarg(cTValue *f)
{
    return frame_typep(f) == FRAME_VARG;
}
static __always_inline ptrdiff_t frame_sized(cTValue *f)
{
    return frame_ftsz(f) & ~FRAME_TYPEP;
}

/* ---- function (closure) ----------------------------------------------- */
#define GCfuncHeader                                                           \
    GCHeader;                                                                  \
    uint8_t ffid;                                                              \
    uint8_t nupvalues;                                                         \
    GCRef env;                                                                 \
    GCRef gclist;                                                              \
    MRef pc

typedef struct GCfuncC {
    GCfuncHeader;
    lua_CFunction f;
    TValue upvalue[1];
} GCfuncC;

typedef struct GCfuncL {
    GCfuncHeader;
    GCRef uvptr[1];
} GCfuncL;

typedef union GCfunc {
    GCfuncC c;
    GCfuncL l;
} GCfunc;

#define FF_LUA 0
#define FF_C   1

static __always_inline GCproto *funcproto(GCfunc *fn)
{
    MRef pc = LUARD_T(fn, l.pc, MRef);
    return (GCproto *)((char *)(unsigned long)mrefu64(pc) - sizeof(GCproto));
}

/* ---- GCobj ------------------------------------------------------------ */
typedef struct GChead {
    GCHeader;
    uint8_t unused1;
    uint8_t unused2;
    GCRef env;
    GCRef gclist;
    GCRef metatable;
} GChead;

typedef union GCobj {
    GChead gch;
    GCstr str;
    GCproto pt;
    GCfunc fn;
} GCobj;

#define obj2gco(v) ((GCobj *)(v))

/* read the GCobj pointer out of the frame's func slot, masking GC tag bits.
 *
 * FR2 layout (lj_frame.h):
 *      ... | func_slot | ftsz_slot |   <- `frame' points at ftsz_slot
 *                   ^- f-1          ^- f
 *   so func is read from frame[-1].gcr .
 * non-FR2 layout: func is the low word of the single slot, tag/ftsz the high.
 */
static __always_inline GCobj *frame_gc(cTValue *frame)
{
    GCRef gcr = LUARD_T(frame - 1, gcr, GCRef);
#if LJ_GC64
    return (GCobj *)(unsigned long)(gcr.gcptr64 & LJ_GCVMASK);
#else
    return (GCobj *)(unsigned long)gcr.gcptr32;
#endif
}

static __always_inline bool valid_user_ptr(uint64_t ptr)
{
    return ptr >= 4096 && ptr <= LJ_GCVMASK;
}

static __always_inline uint8_t gc_type(GCobj *gco)
{
    return LUARD_T(&gco->gch, gct, uint8_t);
}

/* ---- lua_State -------------------------------------------------------- */
struct lua_State {
    GCHeader;
    uint8_t dummy_ffid;
    uint8_t status;
    MRef glref;
    GCRef gclist;
    TValue *base;
    TValue *top;
    MRef maxstack;
    MRef stack;
    GCRef openupval;
    GCRef env;
    void *cframe;
    MSize stacksize;
    void *exdata;
    void *exdata2;
};
typedef struct lua_State lua_State;

#endif /* __LUA_STATE_H */
