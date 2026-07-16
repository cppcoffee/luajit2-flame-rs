# lua-flame

eBPF-based LuaJIT2 CPU flame-graph profiler, written in Rust (user space) and
C (eBPF kernel side). Produces flame graphs that resolve LuaJIT interpreter
frames down to **source file:line** and interleave them with native C frames.

![Example lua-flame output](docs/example-flamegraph.svg)

The image above is a real `folded.svg` generated from the bundled
`tests/cpu-burn.lua` workload with the command shown in [Trying it out](#trying-it-out).

## Architecture

```
target process (nginx / OpenResty / any LuaJIT embedder)
   │
   │  uprobe on lua_resume / lua_pcall     → capture lua_State* per tid
   │  uretprobe on lua_yield                → drop lua_State* per tid
   │  perf-event (CPU clock) @ N Hz         → on each sample:
   │      • bpf_get_stack()  → native user-space IPs
   │      • walk lua_State   → bytecode PC → source line for every frame
   │
   ▼  perf buffer
┌──────────────────────────────────────────────────────────┐
│  Rust user space                                         │
│   libbpf-rs  : load skeleton, attach uprobe/perf-event   │
│   goblin     : find lua_resume/lua_pcall offsets in ELF  │
│   blazesym   : resolve native IPs → C symbol names       │
│   inferno    : folded stacks → flame graph SVG           │
└──────────────────────────────────────────────────────────┘
```

Lua frames are emitted as `L:<chunkname>:<line>` (e.g. `L:api.lua:42`); native
frames as `<symbol>+<offset>`. When a native IP can't be resolved (it's inside
the LuaJIT interpreter), the corresponding Lua frame is substituted in its
place — this is how the Lua call stack is reconstructed on top of the C stack.

## Building

Requirements (Debian/Ubuntu package names):

- `clang` (≥14), `libelf-dev`, `libbpf-dev`, `bpftool` (linux-tools-common)
- Rust ≥ 1.77
- A kernel ≥ 5.13 with BTF (`CONFIG_DEBUG_INFO_BTF=y`)

```sh
cargo build --release
```

The build script (`build.rs`) compiles `bpf/profile.bpf.c` with clang and
generates the libbpf skeleton at compile time via `libbpf-cargo`.

## Usage

The profiler targets a **single PID** that has LuaJIT loaded (as a shared lib
or statically linked). LuaJIT's JIT must be **off** for the interpreter stack
walker to read bytecode PCs:

```lua
jit.off(); jit.flush()
```

The only required flag is `-p/--pid`. By default the profiler samples at 49 Hz,
runs until Ctrl-C, writes folded stacks to `folded.txt`, and writes the flame
graph to `folded.svg`.

```sh
sudo ./target/release/lua-flame -p 1234
```

Use `-F/--frequency` and `-d/--duration` when you want to override those
defaults, for example to take a bounded 99 Hz sample:

```sh
sudo ./target/release/lua-flame -p 1234 -F 99 -d 10 -o folded.txt
```

Options:

| flag | meaning |
|---|---|
| `-p, --pid <PID>` | target process (required) |
| `-F, --frequency <N>` | sample frequency in Hz (default 49) |
| `-d, --duration <S>` | seconds; 0 = until Ctrl-C (default 0) |
| `-U, --user-stacks-only` | omit kernel frames |
| `--lua-user-stacks-only` | show only Lua frames (no native) |
| `--disable-lua` | native-only profiling |
| `-o, --output <FILE>` | folded output path (`.svg` written next to it) |

## Trying it out

A test harness that mimics the nginx/OpenResty "one request = one
`lua_resume`" model is in `tests/`:

```sh
# build LuaJIT (once)
(cd ../luajit2/src && make && make install PREFIX=/usr/local && ldconfig)

# build the C harness that drives lua_resume
cc -O2 tests/harness.c -o /tmp/lua-harness \
   -I/usr/local/include/luajit-2.1 \
   -L/usr/local/lib -lluajit-5.1 -lm -ldl -Wl,-rpath=/usr/local/lib

# start the workload
/tmp/lua-harness tests/cpu-burn.lua &
HPID=$!

# profile for 8 seconds
sudo ./target/release/lua-flame -p $HPID -d 8 -o folded.txt
```

Open `folded.svg` in a browser; you should see `L:cpu-burn.lua:38` and similar
Lua source frames alongside the LuaJIT interpreter C functions (`lj_BC_*`).

## Files

| path | role |
|---|---|
| `bpf/profile.bpf.c` | eBPF program: uprobe capture + perf-event sampler + Lua stack walker |
| `bpf/lua_state.h` | LuaJIT internal structs (lua_State, GCproto, GCfunc, TValue, …) ported for BPF |
| `bpf/common.h` | shared event/struct definitions |
| `bpf/vmlinux.h` | kernel BTF types (x86-64) |
| `src/main.rs` | Rust entry: CLI, attach, perf-buffer aggregation, folded/SVG output |
| `src/perf.rs` | perf_event_open helper |
| `src/syms.rs` | `/proc/pid/maps` + goblin ELF symbol lookup |
| `src/types.rs` | `#[repr(C)]` mirror of `common.h` |
| `tests/cpu-burn.lua` | CPU-burning LuaJIT workload (fib + sum_squares in a coroutine) |
| `tests/harness.c` | C driver that repeatedly calls `lua_resume` |

## Notes / limitations

- The Lua stack walk is bounded to `MAX_LUA_DEPTH` frames (verifier complexity).
  Increase at the cost of BPF verifier pressure.
- `perf_event_paranoid` should be ≤ 1 (`echo 1 | sudo tee /proc/sys/kernel/perf_event_paranoid`).
- GC64 vs non-GC64 is selected at BPF compile time via `-DLJ_TARGET_GC64=1`
  (default for x86-64 OpenResty). For 32-bit builds set it to 0.
- For nginx/OpenResty the uprobe hooks `lua_resume` which fires per-request;
  the standalone LuaJIT `luajit` binary drives everything through one
  `lua_pcall`, so use the bundled `harness.c` (or profile a real OpenResty app).
