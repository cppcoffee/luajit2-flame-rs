/* SPDX-License-Identifier: BSD-2-Clause */
/* eBPF program: sample C + LuaJIT stacks for flame-graph generation.
 *
 * Two independent output streams, both keyed by a per-sample nonce so user
 * space can correlate them:
 *
 *   1. do_perf_event: captures user registers and stack bytes for DWARF
 *      unwinding, plus bpf_get_stack() IPs as a per-sample fallback.
 *   2. walk_lua_stack: emits one `lua_stack_event` per LuaJIT frame.
 *
 * Both carry the same (pid, tid, seq) so the user-space aggregator
 * can stitch the native stack and the Lua stack back together.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "lua_state.h"
#include "common.h"

const volatile bool kernel_stacks_only       = false;
const volatile bool user_stacks_only         = false;
const volatile bool disable_lua_user_trace   = false;
const volatile bool collect_native_stacks    = false;
const volatile bool include_idle             = false;
const volatile pid_t targ_pid                = -1;
const volatile pid_t targ_tid                = -1;

struct lua_state_slot {
	u64 ptr;
	u32 depth;
};

/* per-tid lua_State* and shallow C API nesting depth */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, struct lua_state_slot);
} lua_states SEC(".maps");

/* per-tid sample sequence number (correlates native + lua events) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, u32);
} seq_map SEC(".maps");

/* native stack events */
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} native_events SEC(".maps");

/* lua frame events */
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} lua_events_out SEC(".maps");

/* per-cpu scratch for the native IP array (too big for the BPF stack) */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct native_event);
} native_buf SEC(".maps");

/* per-cpu scratch for emitting lua frames (verifier needs fully-initialized
 * memory passed to bpf_perf_event_output; a per-cpu array starts zeroed). */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct lua_stack_event);
} lua_event_buf SEC(".maps");

#define NO_BCPOS (~(BCPos)0)

/* ---- line number resolution ------------------------------------------ */
static __always_inline int get_lua_line(GCproto *pt, BCPos pc)
{
	MSize sizebc = LUARD_T(pt, sizebc, MSize);
	if (pc > sizebc) return -1;
	BCLine first   = LUARD_T(pt, firstline, BCLine);
	BCLine numline = LUARD_T(pt, numline,   BCLine);
	uint64_t lineinfo_ptr = LUARD_T(pt, lineinfo, MRef).ptr64;
	if (!lineinfo_ptr) return 0;
	if (pc == sizebc) return first + numline;
	if (pc == 0)      return first;
	pc--;
	if (numline < 256) {
		uint8_t v = 0;
		bpf_probe_read_user(&v, 1, (void *)(lineinfo_ptr + pc));
		return first + v;
	} else if (numline < 65536) {
		uint16_t v = 0;
		bpf_probe_read_user(&v, 2, (void *)(lineinfo_ptr + pc * 2));
		return first + v;
	}
	uint32_t v = 0;
	bpf_probe_read_user(&v, 4, (void *)(lineinfo_ptr + pc * 4));
	return first + v;
}

static __always_inline BCPos get_frame_pc(GCfunc *fn, cTValue *prev_frame)
{
	if (prev_frame == NULL) return NO_BCPOS;
	ptrdiff_t ftsz = frame_ftsz(prev_frame);
	int tp = ftsz & FRAME_TYPE;
	uint64_t ins_ptr = 0;
	if (tp == FRAME_LUA) {
		ins_ptr = (uint64_t)frame_pc(prev_frame);
	} else if ((ftsz & FRAME_TYPEP) == FRAME_CONT) {
		ins_ptr = (uint64_t)frame_pc(prev_frame - 2);
	} else {
		return NO_BCPOS;
	}
	if (!ins_ptr) return NO_BCPOS;
	GCproto *pt = funcproto(fn);
	if (!pt) return NO_BCPOS;
	return (BCPos)((BCIns *)ins_ptr - proto_bc(pt)) - 1;
}

/* emit one lua frame as its own perf event */
static __always_inline void emit_lua(struct bpf_perf_event_data *ctx,
	                                     GCobj *gco, cTValue *prev_frame,
	                                     u32 pid, u32 tid, u32 seq, int level,
	                                     bool jit_top)
{
	GCfunc *fn = &gco->fn;

	u32 zero = 0;
	struct lua_stack_event *e = bpf_map_lookup_elem(&lua_event_buf, &zero);
	if (!e) return;
	/* per-cpu array value persists across invocations; reset only the
	 * fields we are about to set. name[] is overwritten by
	 * bpf_probe_read_user_str (which NUL-terminates). */
	e->key.pid = pid;
	e->key.tid = tid;
	e->key.seq = seq;
	e->level = level;
	e->funcp = 0;
	e->line = 0;
	e->type = 0;
	e->name[0] = 0;

	uint8_t ffid = LUARD_T(fn, c.ffid, uint8_t);
	if (ffid == FF_LUA) {
		e->type = jit_top ? FUNC_TYPE_JIT : FUNC_TYPE_LUA;
		GCproto *pt = funcproto(fn);
		if (!pt) return;
		BCPos pc = get_frame_pc(fn, prev_frame);
		BCLine line = LUARD_T(pt, firstline, BCLine);
		if (pc != NO_BCPOS) {
			int r = get_lua_line(pt, pc);
			if (r >= 0) line = r;
		}
		e->line = line;
		uint64_t cn = LUARD_T(pt, chunkname, uint64_t);
		GCstr *str = (GCstr *)(unsigned long)(cn & LJ_GCVMASK);
		if (str) {
			const char *src = (const char *)(str + 1);
			bpf_probe_read_user_str(&e->name, sizeof(e->name), src);
		}
	} else if (ffid == FF_C) {
		e->type = FUNC_TYPE_C;
		e->funcp = (uint64_t)LUARD_T(fn, c.f, lua_CFunction);
	} else {
		e->type = FUNC_TYPE_F;
		e->line = ffid;
	}
	bpf_perf_event_output(ctx, &lua_events_out, BPF_F_CURRENT_CPU,
	                      e, sizeof(*e));
}

/* Walk the materialized Lua VM stack backwards, including an active JIT BASE. */
static __always_inline void walk_lua_stack(struct bpf_perf_event_data *ctx,
                                           u32 tid, u32 pid, u32 seq)
{
	struct lua_state_slot *slot = bpf_map_lookup_elem(&lua_states, &tid);
	if (!slot || !slot->ptr) return;
	lua_State *L = (lua_State *)(unsigned long)slot->ptr;

	uint64_t stack_ptr = LUARD_T(L, stack, MRef).ptr64;
	uint64_t maxstack_ptr = LUARD_T(L, maxstack, MRef).ptr64;
	TValue *bot = (TValue *)(unsigned long)stack_ptr + LJ_FR2;
	TValue *maxstack = (TValue *)(unsigned long)maxstack_ptr;
	uint64_t base_ptr = LUARD_T(L, base, uint64_t);
	bool on_jit_trace = false;

	MRef glref = LUARD_T(L, glref, MRef);
	uint64_t gptr = mrefu64(glref);
	if (valid_user_ptr(gptr)) {
		GCRef cur_L = {};
		MRef jit_base = {};
		bpf_probe_read_user(&cur_L, sizeof(cur_L),
		                    (const void *)(gptr + LJ_G_OFS_CUR_L));
		bpf_probe_read_user(&jit_base, sizeof(jit_base),
		                    (const void *)(gptr + LJ_G_OFS_JIT_BASE));
		uint64_t cur_L_ptr = gcrefu64(cur_L) & LJ_GCVMASK;
		uint64_t jit_base_ptr = mrefu64(jit_base);
		if (cur_L_ptr == (uint64_t)L && jit_base_ptr > (uint64_t)bot &&
		    jit_base_ptr <= (uint64_t)maxstack) {
			base_ptr = jit_base_ptr;
			on_jit_trace = true;
		}
	}

	if (base_ptr <= (uint64_t)bot || base_ptr > (uint64_t)maxstack)
		return;
	TValue *base = (TValue *)(unsigned long)base_ptr;

	cTValue *frame = base - 1;
	cTValue *prev_frame = NULL;
	int out = 0;

	#pragma unroll
	for (int i = 0; i < MAX_LUA_DEPTH; i++) {
		if (frame <= bot || frame >= maxstack) break;
		GCobj *gco = frame_gc(frame);
		uint64_t gco_ptr = (uint64_t)gco;
		bool vararg = frame_isvarg(frame);
		if (!valid_user_ptr(gco_ptr)) break;
		uint8_t gct = gc_type(gco);
		if (gco != obj2gco(L) && !vararg) {
			if (gct != LJ_GCT_FUNC) break;
			emit_lua(ctx, gco, prev_frame, pid, tid, seq, out,
			         on_jit_trace && out == 0);
			out++;
		} else if (!vararg && gct != LJ_GCT_THREAD) {
			break;
		}
		prev_frame = frame;
		if (frame_islua(frame)) {
			const BCIns *pc = frame_pc(frame);
			if (!valid_user_ptr((uint64_t)pc)) break;
			BCIns prev_ins = 0;
			bpf_probe_read_user(&prev_ins, sizeof(prev_ins),
			                    (void *)((char *)pc - sizeof(BCIns)));
			BCReg a = (prev_ins >> 8) & 0xff;
			cTValue *next = frame - (1 + LJ_FR2 + a);
			if (next >= frame || next < bot) break;
			frame = next;
		} else {
			ptrdiff_t size = frame_sized(frame);
			if (size <= 0 || (size & (sizeof(TValue) - 1))) break;
			cTValue *next = (TValue *)((char *)frame - size);
			if (next >= frame || next < bot) break;
			frame = next;
		}
	}
}

static __always_inline void get_pid_tid(u32 *pid, u32 *tid)
{
	u64 id = bpf_get_current_pid_tgid();
	*pid = id >> 32;
	*tid = (u32)id;
}

static __always_inline u32 read_user_stack_snapshot(struct native_event *event)
{
	u32 bytes_read = 0;

	#pragma unroll
	for (u32 offset = 0; offset < USER_STACK_SNAPSHOT_SIZE;
	     offset += USER_STACK_SNAPSHOT_CHUNK_SIZE) {
		if (bpf_probe_read_user(event->stack + offset,
		                        USER_STACK_SNAPSHOT_CHUNK_SIZE,
		                        (const void *)(event->sp + offset)) != 0)
			break;
		bytes_read += USER_STACK_SNAPSHOT_CHUNK_SIZE;
	}

	/* A stack pointer can be less than one chunk below the mapping boundary.
	 * Preserve a useful prefix instead of dropping the entire snapshot. */
	if (bytes_read == 0) {
		if (bpf_probe_read_user(event->stack, 256,
		                        (const void *)event->sp) == 0)
			return 256;
		if (bpf_probe_read_user(event->stack, 128,
		                        (const void *)event->sp) == 0)
			return 128;
		if (bpf_probe_read_user(event->stack, 64,
		                        (const void *)event->sp) == 0)
			return 64;
		if (bpf_probe_read_user(event->stack, 32,
		                        (const void *)event->sp) == 0)
			return 32;
		if (bpf_probe_read_user(event->stack, 16,
		                        (const void *)event->sp) == 0)
			return 16;
		if (bpf_probe_read_user(event->stack, 8,
		                        (const void *)event->sp) == 0)
			return 8;
	}
	return bytes_read;
}

/* bump & fetch the per-tid sample sequence number */
static __always_inline u32 next_seq(u32 tid)
{
	u32 *p = bpf_map_lookup_elem(&seq_map, &tid);
	u32 v = p ? *p + 1 : 1;
	bpf_map_update_elem(&seq_map, &tid, &v, BPF_ANY);
	return v;
}

static __always_inline u64 get_lua_state_arg1(struct pt_regs *ctx)
{
#if defined(__TARGET_ARCH_arm64)
	return *(const volatile u64 *)ctx;
#else
	return (u64)PT_REGS_PARM1(ctx);
#endif
}

/* ---- perf-event sampler ---------------------------------------------- */
SEC("perf_event")
int do_perf_event(struct bpf_perf_event_data *ctx)
{
	u32 pid, tid;
	get_pid_tid(&pid, &tid);
	if (!include_idle && tid == 0) return 0;
	if (targ_pid != -1 && targ_pid != pid) return 0;
	if (targ_tid != -1 && targ_tid != tid) return 0;

	u32 seq = next_seq(tid);

	/* ---- native user-space stack via bpf_get_stack ---- */
	if (!kernel_stacks_only) {
		u32 zero = 0;
		struct native_event *ne = bpf_map_lookup_elem(&native_buf, &zero);
		if (ne) {
				ne->key.pid = pid;
				ne->key.tid = tid;
				ne->key.seq = seq;
			ne->stack_len = 0;
			ne->ip = 0;
			ne->sp = 0;
			ne->fp = 0;
			ne->lr = 0;
			long n = bpf_get_stack(ctx, ne->ips, sizeof(ne->ips),
			                       BPF_F_USER_STACK);
			ne->ip_cnt = n > 0 ? n / sizeof(u64) : 0;
			if (collect_native_stacks) {
				ne->ip = PT_REGS_IP(&ctx->regs);
				ne->sp = PT_REGS_SP(&ctx->regs);
				ne->fp = PT_REGS_FP(&ctx->regs);
			#if defined(__TARGET_ARCH_arm64)
				ne->lr = PT_REGS_RET(&ctx->regs);
			#endif
				if (ne->sp)
					ne->stack_len = read_user_stack_snapshot(ne);
				bpf_perf_event_output(ctx, &native_events, BPF_F_CURRENT_CPU,
				                      ne, sizeof(*ne));
			} else {
				bpf_perf_event_output(ctx, &native_events, BPF_F_CURRENT_CPU,
				                      ne, __builtin_offsetof(struct native_event, stack));
			}
		}
	}

	/* ---- lua frames ---- */
	if (!disable_lua_user_trace)
		walk_lua_stack(ctx, tid, pid, seq);

	return 0;
}

/* ---- uprobe: capture lua_State* on entry to lua_resume/lua_pcall ----- */
SEC("uprobe")
int handle_entry_lua(struct pt_regs *ctx)
{
	u32 pid, tid;
	get_pid_tid(&pid, &tid);
	if (targ_pid != -1 && targ_pid != pid) return 0;
	u64 L = get_lua_state_arg1(ctx);
	if (!L) return 0;
	struct lua_state_slot *old = bpf_map_lookup_elem(&lua_states, &tid);
	struct lua_state_slot slot = {};
	slot.ptr = L;
	slot.depth = 1;
	if (old && old->depth < 0xffff)
		slot.depth = old->depth + 1;
	bpf_map_update_elem(&lua_states, &tid, &slot, BPF_ANY);
	return 0;
}

/* ---- uretprobe: leave lua_resume/lua_pcall/lua_yield ------------------ */
SEC("uretprobe")
int handle_return_lua(struct pt_regs *ctx)
{
	u32 pid, tid;
	get_pid_tid(&pid, &tid);
	if (targ_pid != -1 && targ_pid != pid) return 0;
	struct lua_state_slot *slot = bpf_map_lookup_elem(&lua_states, &tid);
	if (!slot || slot->depth <= 1) {
		bpf_map_delete_elem(&lua_states, &tid);
	} else {
		struct lua_state_slot next = *slot;
		next.depth--;
		bpf_map_update_elem(&lua_states, &tid, &next, BPF_ANY);
	}
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
