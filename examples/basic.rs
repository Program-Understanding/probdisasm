use std::fs;

use probdisasm::{Analysis, Superset, extract_all_hints, extract_text_section};

fn main() -> anyhow::Result<()> {
    let bytes = fs::read("tests/bin/gcc_coreutils_64_O0_make-prime-list.stripped")?;
    let (base, code) = extract_text_section(&bytes, "<input>")?;
    let superset = Superset::new(base, code)?;
    let mut analysis = Analysis::new(&superset);
    analysis.run(&extract_all_hints(&superset));

    for (addr, p) in analysis.sorted_posteriors() {
        if p >= 0.9 {
            let insn = superset
                .at(addr)
                .map(|i| format!("{} {}", i.mnemonic, i.op_str))
                .unwrap_or_default();
            println!("0x{addr:010x}  {insn:<40}  {p:.6}");
        }
    }
    Ok(())
}
