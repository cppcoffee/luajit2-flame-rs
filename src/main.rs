//! lua-flame: eBPF-based LuaJIT2 CPU flame-graph profiler.

mod perf;
mod syms;
mod types;

use anyhow::{anyhow, Context, Result};
use blazesym::symbolize::source::{Process, Source};
use blazesym::symbolize::{Input, Symbolized, Symbolizer};
use clap::Parser;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    PerfBuffer, PerfBufferBuilder,
};
use std::collections::HashMap;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use types::{LuaStackEvent, NativeEvent, SampleKey, FUNC_TYPE_C, FUNC_TYPE_F, FUNC_TYPE_LUA};

mod profile {
    include!(concat!(env!("OUT_DIR"), "/profile.skel.rs"));
}
use profile::ProfileSkelBuilder;

#[derive(Parser, Debug)]
#[command(version, about = "eBPF-based LuaJIT2 flame graph profiler")]
struct Args {
    #[arg(short, long)]
    pid: i32,
    #[arg(short = 'F', long, default_value_t = 49)]
    frequency: u64,
    #[arg(short, long, default_value_t = 0)]
    duration: u64,
    #[arg(short = 'U', long)]
    user_stacks_only: bool,
    #[arg(long)]
    lua_user_stacks_only: bool,
    #[arg(long)]
    disable_lua: bool,
    #[arg(short, long, default_value = "folded.txt")]
    output: String,
}

static EXITING: AtomicBool = AtomicBool::new(false);

/// Aggregated in-flight samples keyed by (pid, tid, seq).
#[derive(Default)]
struct Pending {
    native: HashMap<SampleKey, Vec<u64>>,
    lua: HashMap<SampleKey, Vec<LuaStackEvent>>,
    /// completed folded stacks -> counts
    folded: HashMap<String, u64>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let (lib_path, _base) = syms::find_luajit(args.pid)
        .with_context(|| format!("locating luajit for pid {}", args.pid))?;
    let offs = syms::resolve_lua_offsets(&lib_path)
        .with_context(|| format!("resolving symbols in {}", lib_path.display()))?;
    println!(
        "[+] pid {} -> {}\n    lua_resume={:#x} lua_pcall={:#x} lua_yield={:#x}",
        args.pid,
        lib_path.display(),
        offs.lua_resume,
        offs.lua_pcall,
        offs.lua_yield
    );

    bump_memlock_rlimit()?;

    let mut object = MaybeUninit::<libbpf_rs::OpenObject>::uninit();
    let open_skel = ProfileSkelBuilder::default().open(&mut object)?;
    open_skel.maps.rodata_data.targ_pid = args.pid;
    open_skel.maps.rodata_data.targ_tid = -1;
    open_skel.maps.rodata_data.user_stacks_only = args.user_stacks_only;
    open_skel.maps.rodata_data.disable_lua_user_trace = args.disable_lua;
    let skel = open_skel.load()?;

    // uprobes
    let prog_entry = &skel.progs.handle_entry_lua;
    let links: Vec<libbpf_rs::Link> = vec![
        prog_entry.attach_uprobe(false, -1, &lib_path, offs.lua_resume as usize)?,
        prog_entry.attach_uprobe(false, -1, &lib_path, offs.lua_pcall as usize)?,
        skel.progs.handle_return_lua.attach_uprobe(
            true,
            -1,
            &lib_path,
            offs.lua_resume as usize,
        )?,
        skel.progs
            .handle_return_lua
            .attach_uprobe(true, -1, &lib_path, offs.lua_pcall as usize)?,
        skel.progs
            .handle_return_lua
            .attach_uprobe(true, -1, &lib_path, offs.lua_yield as usize)?,
    ];

    // perf-event sampler
    let nr_cpus = libbpf_rs::num_possible_cpus()?;
    let mut perf_links: Vec<libbpf_rs::Link> = Vec::new();
    for cpu in 0..nr_cpus as i32 {
        let fd = perf::open_cpu_clock(args.frequency, cpu)?;
        perf_links.push(skel.progs.do_perf_event.attach_perf_event(fd)?);
    }

    let pending = Arc::new(Mutex::new(Pending::default()));
    let p1 = pending.clone();
    let p2 = pending.clone();

    // We don't symbolize inside the perf-buffer callbacks (the Symbolizer is
    // not Sync and the Source references a PID). Instead, the callbacks stash
    // raw events; symbolization happens in the finalization pass on the main
    // thread. So we don't need a Symbolizer here at all.
    let _src_unused = Source::Process(Process {
        pid: (args.pid as u32).into(),
        debug_syms: false,
        perf_map: false,
        map_files: false,
        vdso: false,
        _non_exhaustive: (),
    });

    let pb_native: PerfBuffer = PerfBufferBuilder::new(&skel.maps.native_events)
        .pages(64)
        .sample_cb(move |_cpu, data: &[u8]| {
            if let Some(ne) = from_bytes_aligned::<NativeEvent>(data) {
                handle_native(&ne, &p1);
            }
        })
        .build()?;

    let pb_lua: PerfBuffer = PerfBufferBuilder::new(&skel.maps.lua_events_out)
        .pages(64)
        .sample_cb(move |_cpu, data: &[u8]| {
            if let Some(le) = from_bytes_aligned::<LuaStackEvent>(data) {
                handle_lua(le, &p2);
            }
        })
        .build()?;

    println!(
        "[+] sampling at {} Hz for {} ...",
        args.frequency,
        if args.duration == 0 {
            "ever".into()
        } else {
            format!("{}s", args.duration)
        }
    );
    install_ctrlc();
    let start = std::time::Instant::now();

    while !EXITING.load(Ordering::SeqCst) {
        let _ = pb_native.poll(Duration::from_millis(100));
        let _ = pb_lua.poll(Duration::from_millis(100));
        if args.duration > 0 && start.elapsed() >= Duration::from_secs(args.duration) {
            break;
        }
    }
    drop(pb_native);
    drop(pb_lua);

    // finalize: symbolize + fold on the main thread (Symbolizer is not Sync)
    let folded = {
        let src = Source::Process(Process {
            pid: (args.pid as u32).into(),
            debug_syms: true,
            perf_map: false,
            map_files: false,
            vdso: false,
            _non_exhaustive: (),
        });
        let sym = Symbolizer::new();
        let mut g = pending.lock().unwrap();
        let lua_only = args.lua_user_stacks_only;
        let native = std::mem::take(&mut g.native);
        for (seq, ips) in native {
            let lua = g.lua.remove(&seq).unwrap_or_default();
            if let Some(stack) = build_stack(&ips, &lua, &src, &sym, lua_only) {
                *g.folded.entry(stack).or_insert(0) += 1;
            }
        }
        std::mem::take(&mut g.folded)
    };

    write_folded(&folded, std::path::Path::new(&args.output))?;
    let svg = std::path::Path::new(&args.output).with_extension("svg");
    match make_svg(std::path::Path::new(&args.output), &svg) {
        Ok(()) => println!("[+] flame graph SVG: {}", svg.display()),
        Err(e) => println!("[!] SVG generation failed: {e}"),
    }
    drop(links);
    drop(perf_links);
    Ok(())
}

/// Copy raw perf-buffer bytes into a properly-aligned stack value.
/// (`plain::from_bytes` fails on misaligned slices coming from the perf
/// ring buffer.)
fn from_bytes_aligned<T: plain::Plain + Default>(data: &[u8]) -> Option<T> {
    let sz = std::mem::size_of::<T>();
    if data.len() < sz {
        return None;
    }
    let mut val = T::default();
    unsafe {
        std::ptr::copy_nonoverlapping(data.as_ptr(), &mut val as *mut T as *mut u8, sz);
    }
    Some(val)
}

fn handle_native(ne: &NativeEvent, p: &Mutex<Pending>) {
    let cnt = ne.ip_cnt.min(types::PERF_MAX_STACK_DEPTH as u32) as usize;
    let mut g = p.lock().unwrap();
    let ips: Vec<u64> = ne.ips[..cnt].to_vec();
    g.native.insert(ne.key, ips);
}

fn handle_lua(le: LuaStackEvent, p: &Mutex<Pending>) {
    let mut g = p.lock().unwrap();
    g.lua.entry(le.key).or_default().push(le);
}

fn build_stack(
    ips: &[u64],
    lua: &[LuaStackEvent],
    src: &Source,
    sym: &Symbolizer,
    lua_only: bool,
) -> Option<String> {
    let mut native_frames: Vec<Option<String>> = Vec::new();

    for &ip in ips.iter().rev() {
        if ip == 0 {
            continue;
        }
        match sym.symbolize_single(src, Input::AbsAddr(ip)) {
            Ok(Symbolized::Sym(s)) if !s.name.is_empty() => {
                if !lua_only {
                    native_frames.push(Some(format!("{}+{:#x}", s.name, s.offset)));
                } else {
                    native_frames.push(None);
                }
            }
            _ => native_frames.push(None),
        }
    }
    fold_symbolized_stack(&native_frames, lua, lua_only)
}

fn fold_symbolized_stack(
    native_frames: &[Option<String>],
    lua: &[LuaStackEvent],
    lua_only: bool,
) -> Option<String> {
    let mut frames: Vec<String> = Vec::new();
    let mut lua_idx = 0usize;
    let lua_sorted: Vec<LuaStackEvent> = {
        let mut v: Vec<LuaStackEvent> = lua.to_vec();
        v.sort_by_key(|e| std::cmp::Reverse(e.level));
        v
    };

    for native in native_frames {
        if let Some(name) = native {
            if !lua_only {
                frames.push(name.clone());
            }
        } else if lua_idx < lua_sorted.len() {
            if let Some(frame) = format_lua_frame(&lua_sorted[lua_idx]) {
                frames.push(frame);
            }
            lua_idx += 1;
        } else if !lua_only {
            frames.push("[unknown]".into());
        }
    }
    while lua_idx < lua_sorted.len() {
        if let Some(frame) = format_lua_frame(&lua_sorted[lua_idx]) {
            frames.push(frame);
        }
        lua_idx += 1;
    }
    if frames.is_empty() {
        None
    } else {
        Some(frames.join(";"))
    }
}

fn format_lua_frame(ev: &LuaStackEvent) -> Option<String> {
    match ev.r#type {
        FUNC_TYPE_LUA => {
            let chunk = strip_chunkname(&ev.name_str());
            if ev.line > 0 {
                Some(format!("L:{}:{}", chunk, ev.line))
            } else if !chunk.is_empty() {
                Some(format!("L:{}", chunk))
            } else {
                None
            }
        }
        FUNC_TYPE_C => Some(format!("C:{:#x}", ev.funcp)),
        FUNC_TYPE_F => Some(format!("builtin#{}", ev.line)),
        _ => None,
    }
}

fn strip_chunkname(s: &str) -> String {
    let s = s.trim_start_matches('\0');
    let s = s.strip_prefix('@').unwrap_or(s);
    // keep only the basename to avoid truncation noise in flame graphs
    s.rsplit('/').next().unwrap_or(s).to_string()
}

fn write_folded(folded: &HashMap<String, u64>, out: &std::path::Path) -> Result<()> {
    use std::io::Write;
    let mut f = std::io::BufWriter::new(std::fs::File::create(out)?);
    let mut keys: Vec<&String> = folded.keys().collect();
    keys.sort();
    for k in keys {
        writeln!(f, "{} {}", k, folded[k])?;
    }
    println!(
        "[+] wrote {} unique stacks to {}",
        folded.len(),
        out.display()
    );
    Ok(())
}

fn make_svg(folded: &std::path::Path, svg: &std::path::Path) -> Result<()> {
    use inferno::flamegraph::{from_files, Options};
    let mut opts = Options::default();
    opts.title = "lua-flame (LuaJIT + C)".to_string();
    from_files(
        &mut opts,
        &[folded.to_path_buf()],
        std::fs::File::create(svg)?,
    )
    .map_err(|e| anyhow!("inferno: {e}"))?;
    Ok(())
}

fn bump_memlock_rlimit() -> Result<()> {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) } < 0 {
        let err = std::io::Error::last_os_error();
        eprintln!("[!] setrlimit(RLIMIT_MEMLOCK) failed: {err}; continuing");
    }
    Ok(())
}

fn install_ctrlc() {
    unsafe {
        let mut act: libc::sigaction = std::mem::zeroed();
        act.sa_sigaction = handle_sigint as *const () as usize;
        libc::sigemptyset(&mut act.sa_mask);
        libc::sigaction(libc::SIGINT, &act, std::ptr::null_mut());
    }
}

extern "C" fn handle_sigint(_sig: libc::c_int) {
    EXITING.store(true, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lua_event(key: SampleKey, level: i32, name: &str, line: i32) -> LuaStackEvent {
        let mut ev = LuaStackEvent {
            key,
            level,
            r#type: FUNC_TYPE_LUA,
            line,
            ..LuaStackEvent::default()
        };
        let bytes = name.as_bytes();
        let n = bytes.len().min(ev.name.len() - 1);
        ev.name[..n].copy_from_slice(&bytes[..n]);
        ev
    }

    #[test]
    fn folded_stack_uses_lua_root_to_leaf_order() {
        let key = SampleKey {
            pid: 10,
            tid: 20,
            seq: 1,
        };
        let lua = [
            lua_event(key, 0, "@leaf.lua", 30),
            lua_event(key, 2, "@root.lua", 10),
            lua_event(key, 1, "@mid.lua", 20),
        ];
        let native = [
            Some("entry+0x0".to_string()),
            None,
            Some("tail+0x4".to_string()),
        ];

        let folded = fold_symbolized_stack(&native, &lua, false).unwrap();

        assert_eq!(
            folded,
            "entry+0x0;L:root.lua:10;tail+0x4;L:mid.lua:20;L:leaf.lua:30"
        );
    }

    #[test]
    fn folded_stack_lua_only_drops_native_but_keeps_lua() {
        let key = SampleKey {
            pid: 10,
            tid: 20,
            seq: 2,
        };
        let lua = [lua_event(key, 0, "@/srv/app.lua", 42)];
        let native = [Some("native+0x1".to_string()), None];

        let folded = fold_symbolized_stack(&native, &lua, true).unwrap();

        assert_eq!(folded, "L:app.lua:42");
    }

    #[test]
    fn pending_uses_tid_as_part_of_sample_key() {
        let pending = Mutex::new(Pending::default());
        let k1 = SampleKey {
            pid: 100,
            tid: 11,
            seq: 1,
        };
        let k2 = SampleKey {
            pid: 100,
            tid: 12,
            seq: 1,
        };
        let mut ne1 = NativeEvent {
            key: k1,
            ip_cnt: 1,
            ..NativeEvent::default()
        };
        ne1.ips[0] = 0x1111;
        let mut ne2 = NativeEvent {
            key: k2,
            ip_cnt: 1,
            ..NativeEvent::default()
        };
        ne2.ips[0] = 0x2222;

        handle_native(&ne1, &pending);
        handle_native(&ne2, &pending);
        handle_lua(lua_event(k1, 0, "@one.lua", 1), &pending);
        handle_lua(lua_event(k2, 0, "@two.lua", 2), &pending);

        let guard = pending.lock().unwrap();
        assert_eq!(guard.native[&k1], vec![0x1111]);
        assert_eq!(guard.native[&k2], vec![0x2222]);
        assert_eq!(guard.lua[&k1][0].name_str(), "@one.lua");
        assert_eq!(guard.lua[&k2][0].name_str(), "@two.lua");
    }

    #[test]
    fn lua_frame_formatting_handles_known_types() {
        let key = SampleKey::default();
        let lua = lua_event(key, 0, "@/a/b/c.lua", 99);
        assert_eq!(format_lua_frame(&lua).unwrap(), "L:c.lua:99");

        let c = LuaStackEvent {
            r#type: FUNC_TYPE_C,
            funcp: 0x1234,
            ..LuaStackEvent::default()
        };
        assert_eq!(format_lua_frame(&c).unwrap(), "C:0x1234");

        let builtin = LuaStackEvent {
            r#type: FUNC_TYPE_F,
            line: 7,
            ..LuaStackEvent::default()
        };
        assert_eq!(format_lua_frame(&builtin).unwrap(), "builtin#7");
    }

    #[test]
    fn lua_frame_formatting_drops_empty_lua_frames() {
        let empty = LuaStackEvent {
            r#type: FUNC_TYPE_LUA,
            line: 0,
            ..LuaStackEvent::default()
        };

        assert_eq!(format_lua_frame(&empty), None);
    }
}
