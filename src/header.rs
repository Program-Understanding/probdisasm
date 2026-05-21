//! Interfaces with goblin to extract the `.text` section of an ELF. This module will help interact with the headers of ELF files and eventually other executable formats.
use anyhow::{Context, Result, anyhow};
use goblin::elf::Elf;

/// Locate the `.text` section of an ELF and return its load address and bytes.
pub fn extract_text_section<'a>(buffer: &'a [u8], path: &str) -> Result<(u64, &'a [u8])> {
    let elf = Elf::parse(buffer).with_context(|| format!("failed to parse ELF: {}", path))?;
    let text_hdr = elf
        .section_headers
        .iter()
        .find(|s| elf.shdr_strtab.get_at(s.sh_name) == Some(".text"))
        .ok_or_else(|| anyhow!(".text section not found"))?;
    let range = text_hdr
        .file_range()
        .ok_or_else(|| anyhow!(".text has no file range"))?;
    Ok((text_hdr.sh_addr, &buffer[range]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_text_section() {
        let buffer = include_bytes!("../tests/bins/gcc_coreutils_64_O0_make-prime-list.stripped");
        let result = extract_text_section(buffer, "gcc_coreutils_64_O0_make-prime-list.stripped");
        assert!(result.is_ok());
    }

    #[test]
    fn test_extract_text_section_not_found() {
        let buffer = &[0u8; 64];
        let result = extract_text_section(buffer, "gcc_coreutils_64_O0_make-prime-list.stripped");
        assert!(result.is_err());
    }
}
