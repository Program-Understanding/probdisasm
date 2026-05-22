//! Interfaces with goblin to extract the `.text` section of an ELF. This module will help interact with the headers of ELF files and eventually other executable formats.
use anyhow::{Result, anyhow};
use goblin::Object;

/// Locate the `.text` section of an executable and returns its load address and bytes.
pub fn extract_text_section<'a>(buffer: &'a [u8]) -> Result<(u64, &'a [u8])> {
    match goblin::Object::parse(buffer)? {
        Object::Elf(elf) => {
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
        Object::PE(pe) => {
            let text_hdr = pe
                .sections
                .iter()
                .find(|s| s.name().map_or(false, |n| n == ".text"))
                .ok_or_else(|| anyhow!(".text section not found"))?;
            let start = text_hdr.pointer_to_raw_data as usize;
            let end = start
                .checked_add(text_hdr.size_of_raw_data as usize)
                .ok_or_else(|| anyhow!(".text size overflow"))?;
            let load_address = pe.image_base as u64 + text_hdr.virtual_address as u64;
            Ok((load_address, &buffer[start..end]))
        }
        _ => Err(anyhow!("Unsupported binary format")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_text_section_elf() {
        let buffer = include_bytes!("../tests/bins/elf_test");
        let result = extract_text_section(buffer);
        assert!(result.is_ok());
    }

    #[test]
    fn test_extract_text_section_pe() {
        let buffer = include_bytes!("../tests/bins/pe_test.exe");
        let result = extract_text_section(buffer);
        assert!(result.is_ok());
    }

    #[test]
    fn test_extract_text_section_not_found() {
        let buffer = &[0u8; 64];
        let result = extract_text_section(buffer);
        assert!(result.is_err());
    }
}
