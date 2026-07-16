//! Locate the LuaJIT shared library backing a target PID, and resolve the
//! file offsets of the entry points we uprobe (`lua_resume`, `lua_pcall`,
//! `lua_yield`).

use anyhow::{anyhow, Result};
use goblin::elf::program_header::{PF_X, PT_LOAD};
use goblin::elf::sym::STT_FUNC;
use goblin::elf::Elf;
use std::fs;
use std::path::PathBuf;

/// Parse `/proc/<pid>/maps` and find the first mapping whose path contains
/// `luajit` (covers both `libluajit-5.1.so` and a statically-linked
/// `luajit` binary). Returns (lib_path, load_base_address).
pub fn find_luajit(pid: i32) -> Result<(PathBuf, u64)> {
    let maps = fs::read_to_string(format!("/proc/{pid}/maps"))?;
    for line in maps.lines() {
        // format: address perms offset dev inode  pathname
        let mut it = line.split_whitespace();
        let range = it.next().unwrap_or("");
        let _perms = it.next();
        let _offset = it.next();
        let _dev = it.next();
        let _inode = it.next();
        let path = it.next().unwrap_or("");
        if path.to_lowercase().contains("luajit") {
            let base = range
                .split('-')
                .next()
                .ok_or_else(|| anyhow!("bad address range"))?;
            let base = u64::from_str_radix(base, 16)?;
            return Ok((PathBuf::from(path), base));
        }
    }
    Err(anyhow!(
        "no luajit mapping found in /proc/{pid}/maps (is the target a LuaJIT process?)"
    ))
}

/// Symbol file offsets we attach uprobes to.
pub struct LuaOffsets {
    pub lua_resume: u64,
    pub lua_pcall: u64,
    pub lua_yield: u64,
}

/// Resolve `lua_resume`, `lua_pcall`, `lua_yield` symbol *file offsets*
/// (not virtual addresses). uprobe attachment wants the offset within the ELF
/// file, so convert symbol vaddrs through the executable PT_LOAD segment.
pub fn resolve_lua_offsets(lib_path: &PathBuf) -> Result<LuaOffsets> {
    let bytes = fs::read(lib_path)?;
    let elf = Elf::parse(&bytes)?;

    let want = ["lua_resume", "lua_pcall", "lua_yield"];
    let mut found = [None; 3];
    for (name, value, typ) in elf
        .syms
        .iter()
        .filter_map(|sym| {
            elf.strtab
                .get_at(sym.st_name)
                .map(|name| (name, sym.st_value, sym.st_type()))
        })
        .chain(elf.dynsyms.iter().filter_map(|sym| {
            elf.dynstrtab
                .get_at(sym.st_name)
                .map(|name| (name, sym.st_value, sym.st_type()))
        }))
    {
        if typ != STT_FUNC {
            continue;
        }
        for (i, w) in want.iter().enumerate() {
            if name == *w {
                found[i] = Some(vaddr_to_file_offset(&elf, value)?);
            }
        }
    }
    let mk = |i: usize| -> Result<u64> {
        found[i].ok_or_else(|| anyhow!("symbol {} not found", want[i]))
    };
    Ok(LuaOffsets {
        lua_resume: mk(0)?,
        lua_pcall: mk(1)?,
        lua_yield: mk(2)?,
    })
}

fn vaddr_to_file_offset(elf: &Elf<'_>, vaddr: u64) -> Result<u64> {
    for ph in &elf.program_headers {
        if ph.p_type == PT_LOAD
            && (ph.p_flags & PF_X) != 0
            && ph.p_vaddr <= vaddr
            && vaddr < ph.p_vaddr.saturating_add(ph.p_memsz)
        {
            return Ok(vaddr - ph.p_vaddr + ph.p_offset);
        }
    }
    Err(anyhow!(
        "symbol vaddr {vaddr:#x} is not inside an executable PT_LOAD segment"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use goblin::elf::program_header::{PF_X, PT_LOAD};

    #[test]
    fn resolves_offsets_from_built_luajit_shared_object() {
        let path = luajit_src_dir().join("libluajit.so");
        if !path.exists() {
            eprintln!("skipping: {} does not exist", path.display());
            return;
        }

        let offsets = resolve_lua_offsets(&path).unwrap();

        assert!(offsets.lua_resume > 0);
        assert!(offsets.lua_pcall > 0);
        assert!(offsets.lua_yield > 0);

        let bytes = fs::read(&path).unwrap();
        let elf = Elf::parse(&bytes).unwrap();
        for off in [offsets.lua_resume, offsets.lua_pcall, offsets.lua_yield] {
            assert!(elf.program_headers.iter().any(|ph| {
                ph.p_type == PT_LOAD
                    && (ph.p_flags & PF_X) != 0
                    && ph.p_offset <= off
                    && off < ph.p_offset.saturating_add(ph.p_filesz)
            }));
        }
    }

    fn luajit_src_dir() -> PathBuf {
        if let Ok(path) = std::env::var("LUAJIT_SRC_DIR") {
            return PathBuf::from(path);
        }
        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
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
}
