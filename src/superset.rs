// src/superset.rs

use capstone::arch::x86::ArchMode;
use capstone::prelude::*;

#[derive(Debug, Clone)]
pub struct Instruction {
    pub address: u64, // instruction offset
    pub size: u8,     // size of the instruction
    pub mnemonic: String,
    pub op_str: String,
    pub bytes: Vec<u8>,
    pub regs_read: Vec<u16>,
    pub regs_write: Vec<u16>,
    pub groups: Vec<u8>,
    pub branch_target: Option<u64>,
}

pub struct Superset {
    cs: Capstone,
    base_addr: u64,
    instructions: Vec<Option<Instruction>>,
}

impl Superset {
    pub fn new() -> Result<Self, capstone::Error> {
        let cs = Capstone::new()
            .x86()
            .mode(ArchMode::Mode64)
            .detail(true)
            .build()?;
        Ok(Self {
            cs,
            base_addr: 0,
            instructions: Vec::new(),
        })
    }

    pub fn disassemble(&mut self, base_addr: u64, data: &[u8]) -> Result<(), capstone::Error> {
        self.base_addr = base_addr;
        self.instructions = Vec::with_capacity(data.len());

        for offset in 0..data.len() {
            let addr = base_addr + offset as u64;
            let result = self.cs.disasm_count(&data[offset..], addr, 1);

            let entry = match result {
                Ok(insns) if !insns.is_empty() => {
                    let insn = &insns[0];
                    Some(self.convert_insn(insn))
                }
                _ => None,
            };

            self.instructions.push(entry);
        }
        Ok(())
    }

    fn convert_insn(&self, insn: &capstone::Insn) -> Instruction {
        // Filled in next iteration: extract regs_read/write/groups via insn_detail
        Instruction {
            address: insn.address(),
            size: insn.bytes().len() as u8,
            mnemonic: insn.mnemonic().unwrap_or("").to_string(),
            op_str: insn.op_str().unwrap_or("").to_string(),
            bytes: insn.bytes().to_vec(),
            regs_read: Vec::new(),
            regs_write: Vec::new(),
            groups: Vec::new(),
            branch_target: None,
        }
    }

    pub fn at(&self, addr: u64) -> Option<&Instruction> {
        let offset = addr.checked_sub(self.base_addr)? as usize;
        self.instructions.get(offset)?.as_ref()
    }

    pub fn valid_count(&self) -> usize {
        self.instructions.iter().filter(|i| i.is_some()).count()
    }

    pub fn invalid_count(&self) -> usize {
        self.instructions.iter().filter(|i| i.is_none()).count()
    }

    pub fn iter_valid(&self) -> impl Iterator<Item = &Instruction> {
        self.instructions.iter().filter_map(|i| i.as_ref())
    }
}
