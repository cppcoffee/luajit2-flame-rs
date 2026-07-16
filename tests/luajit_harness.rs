use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

#[test]
fn harness_runs_against_local_luajit2() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let luajit_src = luajit_src_dir(repo);
    let luajit_so = luajit_src.join("libluajit.so");
    if !luajit_so.exists() {
        eprintln!("skipping: {} does not exist", luajit_so.display());
        return;
    }

    let out = std::env::temp_dir().join(format!("lua-flame-harness-{}", std::process::id()));
    let status = Command::new("cc")
        .arg("-O2")
        .arg(repo.join("tests/harness.c"))
        .arg("-o")
        .arg(&out)
        .arg("-I")
        .arg(&luajit_src)
        .arg("-L")
        .arg(&luajit_src)
        .arg("-lluajit")
        .arg("-lm")
        .arg("-ldl")
        .arg(format!("-Wl,-rpath={}", luajit_src.display()))
        .status()
        .expect("failed to execute cc");
    assert!(status.success(), "cc failed with status {status}");

    let output = Command::new(&out)
        .arg(repo.join("tests/cpu-burn.lua"))
        .env("LUA_FLAME_HARNESS_ITERS", "3")
        .env("LUA_FLAME_WORK_ITERS", "100")
        .env("LUA_FLAME_FIB_N", "5")
        .env("LUA_FLAME_SUM_N", "10")
        .output()
        .expect("failed to run harness");
    assert!(
        output.status.success(),
        "harness failed: status={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let _ = std::fs::remove_file(out);
}

fn luajit_src_dir(repo: &Path) -> PathBuf {
    if let Ok(path) = std::env::var("LUAJIT_SRC_DIR") {
        return PathBuf::from(path);
    }
    let deps = repo.join("deps/luajit2/src");
    if deps.join("libluajit.so").exists() {
        return deps;
    }
    let sibling = repo
        .parent()
        .map(|parent| parent.join("luajit2/src"))
        .unwrap_or_else(|| PathBuf::from("../luajit2/src"));
    if sibling.join("libluajit.so").exists() {
        return sibling;
    }
    PathBuf::from("/root/TEMP/luajit2/src")
}
