// src/main.rs

use std::env;
use std::fs;
use std::process;

use anyhow::{Context, Result, anyhow};
use goblin::elf::Elf;

mod superset;

use superset::Superset;
fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: {} <binary>", args[0]);
        process::exit(1);
    }

    let path = &args[1];
    let buffer = fs::read(path).with_context(|| format!("failed to read {}", path))?;
    let elf = Elf::parse(&buffer).with_context(|| format!("failed to parse ELF: {}", path))?;

    // Find .text
    let text_hdr = elf
        .section_headers
        .iter()
        .find(|s| {
            elf.shdr_strtab
                .get_at(s.sh_name)
                .map(|n| n == ".text")
                .unwrap_or(false)
        })
        .ok_or_else(|| anyhow!(".text section not found"))?;

    let base = text_hdr.sh_addr;
    let range = text_hdr
        .file_range()
        .ok_or_else(|| anyhow!(".text has no file range (NOBITS?)"))?;
    let bytes = &buffer[range];

    println!("file:  {}", path);
    println!(".text: {} bytes at 0x{:x}", bytes.len(), base);

    let mut sup = Superset::new().map_err(|e| anyhow!("capstone init failed: {}", e))?;
    sup.disassemble(base, bytes)
        .map_err(|e| anyhow!("disassembly failed: {}", e))?;

    let valid = sup.valid_count();
    let invalid = sup.invalid_count();
    let total = valid + invalid;
    let pct = if total > 0 {
        100.0 * valid as f64 / total as f64
    } else {
        0.0
    };

    println!("valid:   {} / {} ({:.1}%)", valid, total, pct);
    println!("invalid: {}", invalid);

    // Print first few valid instructions as a sanity check
    println!("\nfirst 5 valid instructions:");
    for insn in sup.iter_valid().take(5) {
        println!(
            "  0x{:08x}  {:6} {}  ({} bytes)",
            insn.address, insn.mnemonic, insn.op_str, insn.size
        );
    }

    Ok(())
}
