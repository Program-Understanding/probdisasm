// src/main.rs
use std::fs;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use colored::Colorize;

use probdisasm::{extract_all_hints, extract_text_section, Analysis, Superset};

const POSTERIOR_COL: usize = 64;

/// Probabilistic disassembly via Algorithm 1.
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Path to the ELF binary to analyze.
    binary: String,

    /// Highlight rows with posterior at or above this threshold; rows below are dimmed.
    #[arg(long, default_value_t = 0.0)]
    min: f64,

    /// Hide rows with posterior below `--min` instead of dimming them.
    #[arg(long)]
    hide_below: bool,

    /// Disable colored output.
    #[arg(long)]
    no_color: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.no_color {
        colored::control::set_override(false);
    }

    let buffer = fs::read(&args.binary)
        .with_context(|| format!("failed to read {}", args.binary))?;
    let (base, code) = extract_text_section(&buffer, &args.binary)?;

    let superset = Superset::from_bytes(base, code)
        .map_err(|e| anyhow!("disassembly failed: {}", e))?;
    let priors = extract_all_hints(&superset);
    let mut analysis = Analysis::new(&superset);
    analysis.run(&priors);

    for (addr, posterior) in analysis.sorted_posteriors() {
        let (instruction, posterior_str) = match superset.at(addr) {
            Some(i) if i.op_str.is_empty() => (i.mnemonic.clone(), format!("{:.6}", posterior)),
            Some(i) => (format!("{} {}", i.mnemonic, i.op_str), format!("{:.6}", posterior)),
            None => (String::new(), "(data)".to_string()),
        };

        let prefix = format!("0x{:010x}  ", addr);
        let pad = POSTERIOR_COL
            .saturating_sub(prefix.len() + instruction.len())
            .max(2);
        let line = format!("{}{}{}{}", prefix, instruction, " ".repeat(pad), posterior_str);

        if posterior < args.min {
            if args.hide_below {
                continue;
            }
            println!("{}", line.dimmed());
        } else {
            println!("{}", colorize(&line, posterior));
        }
    }

    Ok(())
}

fn colorize(line: &str, posterior: f64) -> colored::ColoredString {
    if posterior >= 0.95 {
        line.green()
    } else if posterior >= 0.5 {
        line.yellow()
    } else if posterior >= 0.1 {
        line.truecolor(255, 140, 0)
    } else {
        line.red()
    }
}
