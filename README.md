# luajit2-flame-rs

`luajit2-flame-rs` is an eBPF-based CPU flame graph profiler for LuaJIT 2.x. It is
written in Rust for user space and C for the eBPF program. It resolves interpreter
frames down to `source:line`, attributes active JIT traces to their Lua function,
and can preserve native C frames in mixed stacks.

### Lua-only flame graph

![Lua-only luajit2-flame-rs output](docs/example-flamegraph.svg)

This graph was generated from the bundled `tests/cpu-burn.lua` workload using
the default Lua-only output mode.

### C and Lua flame graph

![C and Lua luajit2-flame-rs output](docs/example-flamegraph-mixed.svg)

This graph was generated from the same workload with `--include-c-stacks`, so
native LuaJIT frames are shown together with the Lua source frames.

## Features

- Profiles a running LuaJIT process by PID.
- Captures CPU samples with `perf_event` and eBPF.
- Resolves Lua frames as `L:<chunkname>:<line>`.
- Attributes JIT trace execution as `JIT:<chunkname>:<function-line>`.
- Unwinds native C frames from captured registers and stack bytes using ELF
  DWARF CFI, without requiring frame pointers.
- Interleaves Lua frames with native C frames for mixed-stack analysis.
- Writes folded stacks and an SVG flame graph.

## Runtime requirements

These requirements apply when running either a prebuilt release or a locally
built binary. `luajit2-flame-rs` currently supports x86_64 and aarch64 Linux.

- Linux kernel >= 5.13 with eBPF, uprobes, perf events, and BTF enabled. The
  target kernel must expose readable BTF at `/sys/kernel/btf/vmlinux`.
- `root` privileges are recommended. An unprivileged invocation instead needs
  all capabilities and process-access permissions required by the host kernel
  for eBPF, uprobes, perf events, and the target process.
- `kernel.perf_event_paranoid <= 1`.
- A running process with LuaJIT 2.x loaded.

The release archives contain statically linked binaries, so Rust, Clang,
`libbpf-dev`, and `libelf-dev` are not required on the machine that runs the
profiler.

## Build requirements

These requirements apply only when building from source. Source builds require
Rust >= 1.77, Clang/LLVM for compiling the eBPF program, and the native C
development toolchain used by `libbpf`.

Install the build dependencies on Debian/Ubuntu with:

```sh
sudo apt install build-essential clang llvm pkg-config \
  autoconf automake autopoint bison flex gawk \
  libelf-dev libbpf-dev zlib1g-dev
```

The checked-in `bpf/vmlinux.h` targets x86_64. Before building on aarch64,
install `bpftool` and regenerate the header from the build machine's kernel:

```sh
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h.tmp
mv bpf/vmlinux.h.tmp bpf/vmlinux.h
```

`bpftool` is only needed to regenerate this architecture-specific build input;
the profiler does not invoke it at runtime.

## Quick start

```sh
cargo build --release

# perf_event_paranoid must be <= 1 for sampling.
cat /proc/sys/kernel/perf_event_paranoid

# Run this only if the value is greater than 1.
echo 1 | sudo tee /proc/sys/kernel/perf_event_paranoid

# Profile a running LuaJIT process for 10 seconds.
sudo ./target/release/luajit2-flame-rs -p <PID> -d 10 -o folded.txt
```

The command writes:

- `folded.txt`: folded stack output
- `folded.svg`: rendered flame graph

Open `folded.svg` in a browser to inspect the result.

## Usage

The only required flag is `-p/--pid`:

```sh
sudo ./target/release/luajit2-flame-rs -p 1234
```

By default, `luajit2-flame-rs` samples at 99 Hz, runs until Ctrl-C, emits Lua frames
only, writes folded stacks to `folded.txt`, and writes the flame graph to `folded.svg`.

Example bounded capture:

```sh
sudo ./target/release/luajit2-flame-rs -p 1234 -F 99 -d 10 -o folded.txt
```

Options:

| Flag | Description |
|---|---|
| `-p, --pid <PID>` | Target process PID. Required. |
| `-F, --frequency <N>` | Optional sampling frequency in Hz. Default: `99`. |
| `-d, --duration <S>` | Capture duration in seconds. `0` means until Ctrl-C. Default: `0`. |
| `-U, --user-stacks-only` | Omit kernel frames. |
| `--include-c-stacks` | Include native C frames in addition to Lua frames. |
| `--disable-lua` | Native-only profiling. |
| `-o, --output <FILE>` | Folded output path. The `.svg` file is written next to it. |

## Demo workload

If you do not already have a LuaJIT process to profile, use the bundled test
harness. It mimics the nginx/OpenResty model where each request enters Lua via
`lua_resume`.

```sh
# Build LuaJIT once.
(cd ../luajit2/src && make && make install PREFIX=/usr/local && ldconfig)

# Build the C harness that drives lua_resume.
cc -O2 tests/harness.c -o /tmp/lua-harness \
   -I/usr/local/include/luajit-2.1 \
   -L/usr/local/lib -lluajit-5.1 -lm -ldl -Wl,-rpath=/usr/local/lib

# Start the workload.
/tmp/lua-harness tests/cpu-burn.lua &
HPID=$!

# Profile Lua frames for 8 seconds (the default output mode).
sudo ./target/release/luajit2-flame-rs -p $HPID -d 8 -o folded.txt

# Include native C frames in the same flame graph.
sudo ./target/release/luajit2-flame-rs -p $HPID --include-c-stacks -d 8 -o mixed.txt
```

The demo disables JIT by default for deterministic interpreter line coverage.
Set `LUAJIT2_FLAME_RS_JIT=1` when starting the harness to exercise JIT profiling.

You do not need to build LuaJIT with `-g` for Lua stack frames. Lua source lines
come from LuaJIT runtime metadata, not DWARF debug information. Debug symbols are
only useful when you want more native symbol detail in mixed stacks. Native
unwinding uses `.eh_frame` or `.debug_frame`, which standard Linux toolchains
normally emit even for optimized builds that omit frame pointers.

## Architecture

```text
target process (nginx / OpenResty / any LuaJIT embedder)
   │
   │  uprobe on lua_resume / lua_pcall     → capture lua_State* per tid
   │  uretprobe on lua_yield               → drop lua_State* per tid
   │  perf-event CPU clock @ N Hz          → on each sample:
   │      • registers + user stack bytes   → offline native unwind input
   │      • bpf_get_stack()                → fallback native IPs
   │      • walk lua_State                 → bytecode PC → source line
   │
   ▼  perf buffer
┌──────────────────────────────────────────────────────────┐
│ Rust user space                                          │
│   libbpf-rs  : load skeleton, attach uprobe/perf-event   │
│   goblin     : find lua_resume/lua_pcall offsets in ELF  │
│   framehop   : unwind native frames from ELF DWARF CFI   │
│   blazesym   : resolve native IPs → C symbol names       │
│   inferno    : folded stacks → flame graph SVG           │
└──────────────────────────────────────────────────────────┘
```

The build script compiles `bpf/profile.bpf.c` with `clang` and generates the
Rust libbpf skeleton at compile time via `libbpf-cargo`.

## Releases

Pushing a git tag triggers the release workflow. It builds statically linked
musl Linux artifacts on GitHub-hosted x86_64 and aarch64 runners, then uploads
both tarballs and SHA-256 checksums to the matching GitHub Release:

- `luajit2-flame-rs-<tag>-x86_64-unknown-linux-musl.tar.gz`
- `luajit2-flame-rs-<tag>-aarch64-unknown-linux-musl.tar.gz`

The release jobs build on native runners instead of cross-compiling because the
binary embeds a libbpf-generated eBPF skeleton. libbpf, libelf, and zlib are
built from vendored sources and linked statically; the workflow rejects any
binary with a dynamic interpreter or dependency. It tries to regenerate
`bpf/vmlinux.h` from the runner's BTF data and falls back to the checked-in
header if the runner does not expose a usable `bpftool`.

## Limitations

- The Lua stack walk is bounded by `MAX_LUA_DEPTH` to keep eBPF verifier
  complexity manageable.
- Native DWARF unwinding captures up to 4 KiB from the user stack in bounded
  chunks and is limited to 32 frames. A sample falls back to `bpf_get_stack()`
  when offline unwinding cannot recover a usable stack.
- JIT-generated machine code has no ELF DWARF CFI, so its native portion uses
  the fallback stack. LuaJIT runtime metadata still provides the `JIT:` frame.
- `L:` interpreter frames identify the sampled source line. `JIT:` frames identify
  the materialized Lua function running on a trace; optimized inline frames and the
  exact source line within a trace are not reconstructed.
- GC64 vs non-GC64 is selected at BPF compile time with `-DLJ_TARGET_GC64=1`
  by default for 64-bit OpenResty-style LuaJIT builds.
- Standalone `luajit` usually drives execution through one `lua_pcall`; for a
  more realistic `lua_resume` workload, use the bundled harness or profile a
  real nginx/OpenResty process.
