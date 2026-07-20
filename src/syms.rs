//! Locate the ELF containing LuaJIT for a target PID, and resolve the file
//! offsets of the entry points we uprobe (`lua_resume`, `lua_pcall`,
//! `lua_yield`).

use anyhow::{anyhow, Result};
use object::read::ObjectSymbol;
use object::{Object, ObjectSegment, SegmentFlags, SymbolKind};
use std::fs;
use std::path::{Path, PathBuf};

/// Find the ELF that contains LuaJIT. Statically linked programs keep the
/// required symbols in their main executable; dynamically linked programs
/// expose them from a `luajit` mapping.
pub fn find_luajit(pid: i32) -> Result<PathBuf> {
    let executable = PathBuf::from(format!("/proc/{pid}/exe"));
    if resolve_lua_offsets(&executable).is_ok() {
        return Ok(executable);
    }

    let maps = fs::read_to_string(format!("/proc/{pid}/maps"))?;
    for line in maps.lines() {
        let path = line.split_ascii_whitespace().nth(5).unwrap_or("");
        if path.to_lowercase().contains("luajit") {
            return Ok(PathBuf::from(path));
        }
    }
    Err(anyhow!(
        "no LuaJIT symbols found in /proc/{pid}/exe or its shared-library mappings"
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
pub fn resolve_lua_offsets(lib_path: &Path) -> Result<LuaOffsets> {
    let bytes = fs::read(lib_path)?;
    let elf = object::File::parse(bytes.as_slice())?;

    let want = ["lua_resume", "lua_pcall", "lua_yield"];
    let mut found = [None; 3];
    for sym in elf.symbols().chain(elf.dynamic_symbols()) {
        if sym.kind() != SymbolKind::Text || !sym.is_definition() {
            continue;
        }
        let Ok(name) = sym.name_bytes() else { continue };
        let vaddr = sym.address();
        for (i, w) in want.iter().enumerate() {
            if name == w.as_bytes() {
                found[i] = Some(vaddr_to_file_offset(&elf, vaddr)?);
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

fn vaddr_to_file_offset(elf: &object::File<'_>, vaddr: u64) -> Result<u64> {
    const PF_X: u32 = 1;
    // ObjectSegment only iterates PT_LOAD segments, so no p_type check needed.
    for seg in elf.segments() {
        let SegmentFlags::Elf { p_flags } = seg.flags() else {
            continue;
        };
        let p_vaddr = seg.address();
        let p_memsz = seg.size();
        if (p_flags & PF_X) != 0 && p_vaddr <= vaddr && vaddr < p_vaddr.saturating_add(p_memsz) {
            let (p_offset, _) = seg.file_range();
            return Ok(vaddr - p_vaddr + p_offset);
        }
    }
    Err(anyhow!(
        "symbol vaddr {vaddr:#x} is not inside an executable PT_LOAD segment"
    ))
}
