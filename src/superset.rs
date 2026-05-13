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
    pub bytes: Vec<u8>,
    pub regs_read: Vec<u16>,
    pub regs_write: Vec<u16>,
    pub groups: Vec<u8>,
    pub branch_target: Option<u64>,
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

    pub fn disassemble(&mut self, base_addr: u64, data: &[u8]) -> Result<(), capstone::Error> {
        self.base_addr = base_addr;
        self.bytes = data.to_vec();
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
        let mut groups: Vec<u8> = Vec::new();
        let mut regs_read: Vec<u16> = Vec::new();
        let mut regs_write: Vec<u16> = Vec::new();
        let mut branch_target: Option<u64> = None;

        if let Ok(detail) = self.cs.insn_detail(insn) {
            groups = detail.groups().iter().map(|g| g.0).collect();
            regs_read = detail.regs_read().iter().map(|r| r.0).collect();
            regs_write = detail.regs_write().iter().map(|r| r.0).collect();

            let is_branch = groups.iter().any(|&g| {
                let g = g as u32;
                g == InsnGroupType::CS_GRP_JUMP || g == InsnGroupType::CS_GRP_CALL
            });
            if is_branch {
                if let Some(x86) = detail.arch_detail().x86() {
                    // Capstone resolves PC-relative direct branches to absolute
                    // target addresses, exposed as an immediate operand.
                    for op in x86.operands() {
                        if let X86OperandType::Imm(v) = op.op_type {
                            branch_target = Some(v as u64);
                            break;
                        }
                    }
                }
            }
        }

        Instruction {
            address: insn.address(),
            size: insn.bytes().len() as u8,
            mnemonic: insn.mnemonic().unwrap_or("").to_string(),
            op_str: insn.op_str().unwrap_or("").to_string(),
            bytes: insn.bytes().to_vec(),
            regs_read,
            regs_write,
            groups,
            branch_target,
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

    /// Intraprocedural control-flow successors of `addr`. Calls take the
    /// fall-through (we don't follow into callees). Returns empty for `ret`
    /// or for addresses that don't decode.
    pub fn successors_of(&self, addr: u64) -> Vec<u64> {
        let insn = match self.at(addr) {
            Some(i) => i,
            None => return Vec::new(),
        };

        let is_jump = insn.groups.iter().any(|&g| g as u32 == InsnGroupType::CS_GRP_JUMP);
        let is_ret = insn.groups.iter().any(|&g| g as u32 == InsnGroupType::CS_GRP_RET);

        if is_ret {
            return Vec::new();
        }

        let next = addr + insn.size as u64;
        let mut out = Vec::new();
        if is_jump {
            if let Some(target) = insn.branch_target {
                out.push(target);
            }
            let is_unconditional_jmp = insn.mnemonic == "jmp";
            if !is_unconditional_jmp {
                out.push(next);
            }
            return out;
        }

        out.push(next);
        out
    }
}
