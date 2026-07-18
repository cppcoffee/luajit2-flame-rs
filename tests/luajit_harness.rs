use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

/// Set this to make a missing LuaJIT build a hard failure instead of a skip.
/// CI sets it so a broken checkout can never silently disable this test.
const REQUIRED_ENV: &str = "LUAJIT2_FLAME_RS_HARNESS_REQUIRED";

#[test]
fn harness_runs_against_local_luajit2() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let Some(luajit_src) = find_luajit_src(repo) else {
        let msg = format!(
            "LuaJIT harness test skipped: libluajit.so not found in any candidate location.\n\
             Searched: $LUAJIT_SRC_DIR, deps/luajit2/src, <repo>/../luajit2/src.\n\
             Build LuaJIT in one of those locations, or point $LUAJIT_SRC_DIR at a built \
             luajit2/src directory.\n\
             Set {REQUIRED_ENV}=1 to turn this skip into a failure."
        );
        if std::env::var_os(REQUIRED_ENV).is_some() {
            panic!("{msg}");
        }
        eprintln!("{msg}");
        return;
    };
    let luajit_so = luajit_src.join("libluajit.so");

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

    for jit in ["0", "1"] {
        let output = Command::new(&out)
            .arg(repo.join("tests/cpu-burn.lua"))
            .env("LUAJIT2_FLAME_RS_HARNESS_ITERS", "3")
            .env("LUAJIT2_FLAME_RS_WORK_ITERS", "100")
            .env("LUAJIT2_FLAME_RS_FIB_N", "5")
            .env("LUAJIT2_FLAME_RS_SUM_N", "10")
            .env("LUAJIT2_FLAME_RS_JIT", jit)
            .output()
            .expect("failed to run harness");
        assert!(
            output.status.success(),
            "harness failed with JIT={jit}: status={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let _ = std::fs::remove_dir_all(temp);
}

/// First directory containing a built `libluajit.so`, or `None` when no
/// usable LuaJIT checkout exists on this machine.
fn find_luajit_src(repo: &Path) -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(path) = std::env::var_os("LUAJIT_SRC_DIR") {
        candidates.push(PathBuf::from(path));
    }
    candidates.push(repo.join("deps/luajit2/src"));
    if let Some(parent) = repo.parent() {
        candidates.push(parent.join("luajit2/src"));
    }
    candidates
        .into_iter()
        .find(|dir| dir.join("libluajit.so").exists())
}
