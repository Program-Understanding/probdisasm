// src/superset.rs

use capstone::InsnGroupType;
use capstone::arch::DetailsArchInsn;
use capstone::arch::x86::{ArchMode, X86OperandType};
use capstone::prelude::*;

#[derive(Debug, Clone)]
pub struct Instruction {
    pub address: u64, // instruction offset
    pub size: u8,     // size of the instruction
    pub mnemonic: String,
    pub op_str: String,
    pub regs_read: Vec<u16>,
    pub regs_write: Vec<u16>,
    pub groups: Vec<u8>,
    pub branch_target: Option<u64>,
}

impl Instruction {
    pub fn is_jump(&self) -> bool {
        self.has_group(InsnGroupType::CS_GRP_JUMP)
    }

    pub fn is_call(&self) -> bool {
        self.has_group(InsnGroupType::CS_GRP_CALL)
    }

    pub fn is_ret(&self) -> bool {
        self.has_group(InsnGroupType::CS_GRP_RET)
    }

    pub fn has_group(&self, group: u32) -> bool {
        self.groups.iter().any(|&g| g as u32 == group)
    }

    pub fn is_branch(&self) -> bool {
        self.is_jump() || self.is_call()
    }
}
pub struct Superset {
    cs: Capstone,
    pub base_addr: u64,
    pub bytes: Vec<u8>,
    pub instructions: Vec<Option<Instruction>>,
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
            bytes: Vec::new(),
            instructions: Vec::new(),
        })
    }

    pub fn from_bytes(base_addr: u64, bytes: &[u8]) -> Result<Self, capstone::Error> {
        let mut sup = Self::new()?;
        sup.disassemble(base_addr, bytes)?;
        Ok(sup)
    }

    pub fn disassemble(&mut self, base_addr: u64, data: &[u8]) -> Result<(), capstone::Error> {
        self.base_addr = base_addr;
        self.bytes = data.to_vec();
        self.instructions = (0..data.len())
            .map(|offset| {
                let addr = base_addr + offset as u64;
                self.cs
                    .disasm_count(&data[offset..], addr, 1)
                    .ok()
                    .and_then(|insns| insns.iter().next().map(|i| self.convert_insn(i)))
            })
            .collect();
        Ok(())
    }

    fn convert_insn(&self, insn: &capstone::Insn) -> Instruction {
        let mut result_insn = Instruction {
            address: insn.address(),
            size: insn.bytes().len() as u8,
            mnemonic: insn.mnemonic().unwrap_or("").to_string(),
            op_str: insn.op_str().unwrap_or("").to_string(),
            // bytes: insn.bytes().to_vec(),
            regs_read: Vec::new(),
            regs_write: Vec::new(),
            groups: Vec::new(),
            branch_target: None,
        };

        let Ok(detail) = self.cs.insn_detail(insn) else {
            return result_insn;
        };
        result_insn.groups = detail.groups().iter().map(|g| g.0).collect();
        result_insn.regs_read = detail.regs_read().iter().map(|r| r.0).collect();
        result_insn.regs_write = detail.regs_write().iter().map(|r| r.0).collect();
        result_insn.branch_target = extract_branch_target(&detail, &result_insn.groups);
        result_insn
    }

    pub fn at(&self, addr: u64) -> Option<&Instruction> {
        let offset = addr.checked_sub(self.base_addr)? as usize;
        self.instructions.get(offset)?.as_ref()
    }

    pub fn iter_valid(&self) -> impl Iterator<Item = &Instruction> {
        self.instructions.iter().filter_map(|i| i.as_ref())
    }

    /// Intraprocedural control-flow successors of `addr`. Calls take the
    /// fall-through (we don't follow into callees). Returns empty for `ret`
    /// or for addresses that don't decode.
    pub fn successors_of(&self, addr: u64) -> Vec<u64> {
        let Some(insn) = self.at(addr) else {
            return Vec::new();
        };

        if insn.is_ret() {
            return Vec::new();
        }

        let fall_through = addr + insn.size as u64;

        if !insn.is_jump() {
            return vec![fall_through];
        }
        let mut out = Vec::new();
        if let Some(target) = insn.branch_target {
            out.push(target);
        }
        if insn.mnemonic != "jmp" {
            out.push(fall_through);
        }
        out
    }
}

fn extract_branch_target(detail: &InsnDetail, groups: &[u8]) -> Option<u64> {
    let is_branch = groups.iter().any(|&g| {
        matches!(
            g as u32,
            InsnGroupType::CS_GRP_JUMP | InsnGroupType::CS_GRP_CALL // check if it belongs to the call or jump group.
        )
    });
    if !is_branch {
        return None;
    }

    detail
        .arch_detail()
        .x86()?
        .operands()
        .find_map(|op| match op.op_type {
            X86OperandType::Imm(v) => Some(v as u64),
            _ => None,
        })
}
