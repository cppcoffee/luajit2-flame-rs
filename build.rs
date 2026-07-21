// Build script: compiles the eBPF C program and generates the Rust skeleton.
use libbpf_cargo::SkeletonBuilder;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let bpf_src = PathBuf::from("bpf/profile.bpf.c");
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let obj_out = PathBuf::from(&out_dir).join("profile.bpf.o");
    let skel_out = PathBuf::from(&out_dir).join("profile.skel.rs");

    let target_arch =
        std::env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH not set");
    let (bpf_arch, multiarch_include) = match target_arch.as_str() {
        "x86_64" => ("x86", "x86_64-linux-gnu"),
        "aarch64" => ("arm64", "aarch64-linux-gnu"),
        other => panic!("unsupported target architecture for BPF build: {other}"),
    };

    // The checked-in bpf/vmlinux.h is x86_64-only. On any other target we must
    // regenerate it from the host kernel's BTF (the release CI builds each
    // target on a same-arch runner, so /sys/kernel/btf/vmlinux matches).
    let mut clang_includes: Vec<String> = Vec::new();
    if target_arch != "x86_64" {
        let regenerated = PathBuf::from(&out_dir).join("vmlinux.h");
        match Command::new("bpftool")
            .args([
                "btf",
                "dump",
                "file",
                "/sys/kernel/btf/vmlinux",
                "format",
                "c",
            ])
            .output()
        {
            Ok(out) if out.status.success() && !out.stdout.is_empty() => {
                std::fs::write(&regenerated, &out.stdout).expect("writing regenerated vmlinux.h");
                clang_includes.push(format!("-I{}", out_dir));
            }
            Ok(out) => panic!(
                "bpftool failed to dump /sys/kernel/btf/vmlinux (status {}): {}{}",
                out.status,
                String::from_utf8_lossy(&out.stderr),
                String::from_utf8_lossy(&out.stdout),
            ),
            Err(_) => panic!(
                "bpftool not found; install linux-tools-common (or linux-tools-generic) \
                 so vmlinux.h can be regenerated for the {target_arch} BPF build"
            ),
        }
    }
    clang_includes.push(format!("-I/usr/include/{multiarch_include}"));
    clang_includes.push("-Ibpf".into());

    // OpenResty LuaJIT2 defaults to GC64 on the 64-bit Linux architectures we
    // release. This must match the target LuaJIT layout read by the BPF walker.
    let gc64 = "1";

    let mut clang_args: Vec<String> = vec![
        "-g".into(),
        "-O2".into(),
        "-target".into(),
        "bpf".into(),
        format!("-D__TARGET_ARCH_{bpf_arch}"),
        format!("-DLJ_TARGET_GC64={gc64}"),
    ];
    clang_args.extend(clang_includes);

    let mut builder = SkeletonBuilder::new();
    let result = builder
        .source(bpf_src.clone())
        .obj(&obj_out)
        .clang_args(&clang_args)
        .build_and_generate(&skel_out);

    if let Err(e) = result {
        panic!("skeleton generation failed: {e}");
    }

    println!("cargo:rerun-if-changed={}", bpf_src.display());
    println!("cargo:rerun-if-changed=bpf/lua_state.h");
    println!("cargo:rerun-if-changed=bpf/common.h");
    println!("cargo:rerun-if-changed=bpf/vmlinux.h");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_ARCH");
}
