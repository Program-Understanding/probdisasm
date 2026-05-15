// src/main.rs

use std::env;
use std::fs;
use std::io::Write;
use std::process;
use std::collections::HashMap;
use anyhow::{Context, Result, anyhow};
use goblin::elf::Elf;

mod superset;
mod analysis;
mod hints;

use superset::Superset;
use analysis::Analysis;

use hints::extract_all_hints;
fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args.len() > 3 {
        eprintln!("usage: {} <binary> [posteriors.csv]", args[0]);
        process::exit(1);
    }

    let path = &args[1];
    let out_csv = args.get(2);
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


    println!("\nextracting hints...");
    let hint_priors = extract_all_hints(&sup);
    println!("hints: {} extracted", hint_priors.len());

    // Breakdown by label
    let mut by_label: HashMap<hints::HintLabel, usize> = HashMap::new();
    for key in hint_priors.keys() {
        *by_label.entry(key.label).or_insert(0) += 1;
    }
    for (label, count) in &by_label {
        println!("  {:?}: {}", label, count);
    }

    println!("\nrunning algorithm 1...");
    let mut analysis = Analysis::new(&sup);
    analysis.run(&hint_priors);

    let mut posteriors: Vec<(u64, f64)> = analysis.posteriors().iter().map(|(&a, &p)| (a, p)).collect();
    posteriors.sort_by_key(|(a, _)| *a);
    println!("posteriors computed: {}", posteriors.len());

    for threshold in [0.99, 0.9, 0.5, 0.1, 0.01] {
        let n = posteriors.iter().filter(|(_, p)| *p >= threshold).count();
        println!("  P >= {:.2}: {}", threshold, n);
    }

    if let Some(out_path) = out_csv {
        let mut f = fs::File::create(out_path)
            .with_context(|| format!("failed to create {}", out_path))?;
        writeln!(f, "address,posterior")?;
        for (addr, p) in &posteriors {
            writeln!(f, "{},{}", addr, p)?;
        }
        println!("wrote {} rows to {}", posteriors.len(), out_path);
    }

    Ok(())
}
