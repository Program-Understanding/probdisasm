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
