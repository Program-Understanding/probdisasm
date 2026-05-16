// src/lib.rs
pub mod analysis;
pub mod header;
pub mod hints;
pub mod superset;


use std::collections::HashMap;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

pub use analysis::Analysis;
pub use header::extract_text_section;
pub use hints::{extract_all_hints, HintKey, HintLabel};
pub use superset::{Instruction, Superset};

/// Run probabilistic disassembly on a code section.
pub fn disassemble_section(
    base_addr: u64,
    code: &[u8],
) -> Result<HashMap<u64, f64>, capstone::Error> {
    let superset = Superset::from_bytes(base_addr, code)?;
    let hint_priors = extract_all_hints(&superset);
    let mut analysis = Analysis::new(&superset);
    analysis.run(&hint_priors);
    Ok(analysis.sorted_posteriors().into_iter().collect())
}

// ---- Python bindings ----

/// Run probabilistic disassembly on an ELF binary.
///
/// Returns a list of (address, instruction, posterior) tuples sorted by address.
#[pyfunction]
fn disassemble(elf_bytes: &[u8]) -> PyResult<Vec<(u64, String, f64)>> {
    let (base, code) = extract_text_section(elf_bytes, "<input>")
        .map_err(|e| PyValueError::new_err(format!("{}", e)))?;

    let superset = Superset::from_bytes(base, code)
        .map_err(|e| PyValueError::new_err(format!("disassembly failed: {}", e)))?;
    let hint_priors = extract_all_hints(&superset);
    let mut analysis = Analysis::new(&superset);
    analysis.run(&hint_priors);

    let out = analysis
        .sorted_posteriors()
        .into_iter()
        .map(|(addr, posterior)| {
            let instruction = match superset.at(addr) {
                Some(i) if i.op_str.is_empty() => i.mnemonic.clone(),
                Some(i) => format!("{} {}", i.mnemonic, i.op_str),
                None => String::new(),
            };
            (addr, instruction, posterior)
        })
        .collect();

    Ok(out)
}

#[pyfunction]
#[pyo3(name = "disassemble_section")]
fn disassemble_section_py(
    base_addr: u64,
    code: &[u8],
) -> PyResult<Vec<(u64, String, f64)>> {
    let superset = Superset::from_bytes(base_addr, code)
        .map_err(|e| PyValueError::new_err(format!("disassembly failed: {}", e)))?;
    let hint_priors = extract_all_hints(&superset);
    let mut analysis = Analysis::new(&superset);
    analysis.run(&hint_priors);

    let out = analysis
        .sorted_posteriors()
        .into_iter()
        .map(|(addr, posterior)| {
            let instruction = match superset.at(addr) {
                Some(i) if i.op_str.is_empty() => i.mnemonic.clone(),
                Some(i) => format!("{} {}", i.mnemonic, i.op_str),
                None => String::new(),
            };
            (addr, instruction, posterior)
        })
        .collect();

    Ok(out)
}

#[pymodule]
fn probdisasm(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(disassemble, m)?)?;
    m.add_function(wrap_pyfunction!(disassemble_section_py, m)?)?;
    Ok(())
}
