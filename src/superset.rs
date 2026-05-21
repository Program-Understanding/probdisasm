//! A superset disassembler that performs decoding for every offset or byte in a .text section.
//!
use capstone::InsnGroupType;
use capstone::arch::DetailsArchInsn;
use capstone::arch::x86::{ArchMode, X86OperandType};
use capstone::prelude::*;

/// Represents a disassembled instruction converted from a `capstone::Insn`.
#[derive(Debug, Clone)]
pub struct Instruction {
    /// The instruction offset from the base address.
    pub address: u64,
    /// The size of the instruction in bytes.
    pub size: u8,
    /// The mnemonic of the instruction (e.g., "mov", "add").
    pub mnemonic: String,
    /// The operand string of the instruction (e.g., "eax, ebx").
    pub op_str: String,
    /// The registers read by the instruction.
    pub regs_read: Vec<u16>,
    /// The registers written by the instruction.
    pub regs_write: Vec<u16>,
    /// The groups the instruction belongs to.
    pub groups: Vec<u8>,
    /// The branch target of the instruction.
    pub branch_target: Option<u64>,
}

impl Instruction {
    /// Returns `true` if the instruction is a jump (jmp) instruction.
    pub fn is_jump(&self) -> bool {
        self.has_group(InsnGroupType::CS_GRP_JUMP)
    }

    /// Returns `true` if the instruction is a call (call) instruction.
    pub fn is_call(&self) -> bool {
        self.has_group(InsnGroupType::CS_GRP_CALL)
    }

    /// Returns `true` if the instruction is a return (ret) instruction.
    pub fn is_ret(&self) -> bool {
        self.has_group(InsnGroupType::CS_GRP_RET)
    }

    /// Returns `true` if the instruction has the given group.
    pub fn has_group(&self, group: u32) -> bool {
        self.groups.iter().any(|&g| g as u32 == group)
    }

    /// Returns `true` if the instruction is a branch (jump or call).
    pub fn is_branch(&self) -> bool {
        self.is_jump() || self.is_call()
    }
}

/// A `Superset` is a collection of `Instruction`s that have been exhaustively disassembled for every offset in the given bytes.
pub struct Superset {
    /// The base address of the .text section.
    pub base_addr: u64,
    /// The bytes of the .text section.
    pub bytes: Vec<u8>,
    /// The disassembled instructions, indexed by offset.
    pub instructions: Vec<Option<Instruction>>,
}

impl Superset {
    /// Build a `Superset` by exhaustively disassembling `bytes` at every
    /// offset.
    pub fn new(base_addr: u64, bytes: &[u8]) -> Result<Self, capstone::Error> {
        let cs = Capstone::new()
            .x86()
            .mode(ArchMode::Mode64)
            .detail(true)
            .build()?;

        let instructions = (0..bytes.len())
            .map(|offset| {
                let addr = base_addr + offset as u64;
                cs.disasm_count(&bytes[offset..], addr, 1)
                    .ok()
                    .and_then(|insns| insns.iter().next().map(|i| convert_insn(&cs, i)))
            })
            .collect();

        Ok(Self {
            base_addr,
            bytes: bytes.to_vec(),
            instructions,
        })
    }

    /// Returns the `Instruction` at the given address, if one exists.
    pub fn at(&self, addr: u64) -> Option<&Instruction> {
        let offset = addr.checked_sub(self.base_addr)? as usize;
        self.instructions.get(offset)?.as_ref()
    }

    /// Returns an iterator over all valid `Instruction`s in this `Superset`.
    pub fn iter_valid(&self) -> impl Iterator<Item = &Instruction> {
        self.instructions.iter().filter_map(|i| i.as_ref())
    }

    /// Returns the control flow successors of the given address.
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

/// Convert a `capstone::Insn` to a custom `Instruction`
fn convert_insn(cs: &Capstone, insn: &capstone::Insn) -> Instruction {
    let mut result_insn = Instruction {
        address: insn.address(),
        size: insn.bytes().len() as u8,
        mnemonic: insn.mnemonic().unwrap_or("").to_string(),
        op_str: insn.op_str().unwrap_or("").to_string(),
        regs_read: Vec::new(),
        regs_write: Vec::new(),
        groups: Vec::new(),
        branch_target: None,
    };

    let Ok(detail) = cs.insn_detail(insn) else {
        return result_insn;
    };
    result_insn.groups = detail.groups().iter().map(|g| g.0).collect();
    result_insn.regs_read = detail.regs_read().iter().map(|r| r.0).collect();
    result_insn.regs_write = detail.regs_write().iter().map(|r| r.0).collect();
    result_insn.branch_target = extract_branch_target(&detail, &result_insn.groups);
    result_insn
}

/// Extracts the branch target from the given `InsnDetail` and `groups`.
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

#[cfg(test)]
mod tests {

    use super::*;

    fn build_superset_extract_one(bytes: &[u8], addr: u64) -> Instruction {
        let superset = Superset::new(addr, bytes).expect("Failed to build superset");
        superset
            .at(addr)
            .expect("Failed to extract instruction at address")
            .clone()
    }

    #[test]
    fn test_extract_branch_target_direct_jump() {
        // `jmp 5` -> x64 jump relative to the next instruction
        //  At address 0x1000: 0x1000 +5 (insn size) + 0 (rel32) = 0x1005
        let jmp_bytes: &[u8] = &[0xE9, 0x00, 0x00, 0x00, 0x00];
        let insn = build_superset_extract_one(jmp_bytes, 0x1000);
        assert_eq!(insn.branch_target, Some(0x1005));
    }

    #[test]
    fn test_extract_branch_target_direct_call() {
        // `call 0x20` -> x64 call relative to the next instruction
        //  At address 0x1000: 0x1000 +5 (insn size) + 0 (rel32) = 0x1005
        let call_bytes: &[u8] = &[0xE8, 0x0A, 0x00, 0x00, 0x00];
        let insn = build_superset_extract_one(call_bytes, 0x1000);
        assert_eq!(insn.branch_target, Some(0x100F));
    }
}
