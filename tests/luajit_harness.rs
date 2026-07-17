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

    let temp =
        std::env::temp_dir().join(format!("luajit2-flame-rs-harness-{}", std::process::id()));
    let lib_dir = temp.join("lib");
    std::fs::create_dir_all(&lib_dir).expect("failed to create temporary lib dir");
    let linked_luajit = lib_dir.join("libluajit.so");
    let soname_luajit = lib_dir.join("libluajit-5.1.so.2");
    std::fs::copy(&luajit_so, &linked_luajit).expect("failed to copy libluajit.so");
    std::fs::copy(&luajit_so, &soname_luajit).expect("failed to copy libluajit SONAME");

    let out = temp.join("lua-harness");
    let status = Command::new("cc")
        .arg("-O2")
        .arg(repo.join("tests/harness.c"))
        .arg("-o")
        .arg(&out)
        .arg("-I")
        .arg(&luajit_src)
        .arg("-L")
        .arg(&lib_dir)
        .arg("-lluajit")
        .arg("-lm")
        .arg("-ldl")
        .arg(format!("-Wl,-rpath={}", lib_dir.display()))
        .status()
        .expect("failed to execute cc");
    assert!(status.success(), "cc failed with status {status}");

    let output = Command::new(&out)
        .arg(repo.join("tests/cpu-burn.lua"))
        .env("LUAJIT2_FLAME_RS_HARNESS_ITERS", "3")
        .env("LUAJIT2_FLAME_RS_WORK_ITERS", "100")
        .env("LUAJIT2_FLAME_RS_FIB_N", "5")
        .env("LUAJIT2_FLAME_RS_SUM_N", "10")
        .output()
        .expect("failed to run harness");
    assert!(
        output.status.success(),
        "harness failed: status={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let _ = std::fs::remove_dir_all(temp);
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
