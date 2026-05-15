// src/main.rs
use std::collections::HashMap;
use std::fs;
use std::io::Write;

use anyhow::{Context, Result, anyhow};
use clap::Parser;

mod analysis;
mod header;
mod hints;
mod superset;

use analysis::Analysis;
use hints::{HintKey, HintLabel, extract_all_hints};
use superset::Superset;

/// Probabilistic disassembly via Algorithm 1.
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Path to the ELF binary to analyze.
    binary: String,

    /// Optional output CSV path for (address, posterior) rows.
    output_csv: Option<String>,
}

const POSTERIOR_THRESHOLDS: [f64; 5] = [0.99, 0.9, 0.5, 0.1, 0.01];

fn main() -> Result<()> {
    let args = Args::parse();

    let buffer =
        fs::read(&args.binary).with_context(|| format!("failed to read {}", args.binary))?;
    let (base, text_bytes) = header::extract_text_section(&buffer, &args.binary)?;

    println!("file:  {}", args.binary);
    println!(".text: {} bytes at 0x{:x}", text_bytes.len(), base);

    let superset =
        Superset::from_bytes(base, text_bytes).map_err(|e| anyhow!("disassembly failed: {}", e))?;

    println!("\nextracting hints...");
    let hint_priors = extract_all_hints(&superset);
    println!("hints: {} extracted", hint_priors.len());
    print_hint_breakdown(&hint_priors);

    println!("\nrunning algorithm 1...");
    let mut analysis = Analysis::new(&superset);
    analysis.run(&hint_priors);

    let posteriors = analysis.sorted_posteriors();
    println!("posteriors computed: {}", posteriors.len());
    print_posterior_thresholds(&posteriors);

    if let Some(out_path) = &args.output_csv {
        write_csv(out_path, &posteriors)?;
        println!("wrote {} rows to {}", posteriors.len(), out_path);
    }
    Ok(())
}

fn print_hint_breakdown(hint_priors: &HashMap<HintKey, f64>) {
    let mut by_label: HashMap<HintLabel, usize> = HashMap::new();
    for key in hint_priors.keys() {
        *by_label.entry(key.label).or_insert(0) += 1;
    }
    let mut entries: Vec<(HintLabel, usize)> = by_label.into_iter().collect();
    entries.sort_by_key(|(label, _)| format!("{:?}", label));
    for (label, count) in &entries {
        println!("  {:?}: {}", label, count);
    }
}

fn print_posterior_thresholds(posteriors: &[(u64, f64)]) {
    for threshold in POSTERIOR_THRESHOLDS {
        let count = posteriors.iter().filter(|(_, p)| *p >= threshold).count();
        println!("  P >= {:.2}: {}", threshold, count);
    }
}

fn write_csv(path: &str, posteriors: &[(u64, f64)]) -> Result<()> {
    let mut f = fs::File::create(path).with_context(|| format!("failed to create {}", path))?;
    writeln!(f, "address,posterior")?;
    for (addr, p) in posteriors {
        writeln!(f, "{},{}", addr, p)?;
    }
    Ok(())
}
