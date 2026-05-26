//! Hint extractors from Miller et al. and hopefully future extensions of the hint system.

use std::collections::{HashMap, HashSet};

use crate::superset::{Instruction, Superset};

/// A hint that the address that produced it plus a label for the hint type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HintKey {
    /// The address that produced this hint.
    pub source_addr: u64,
    /// The type of hint.
    pub label: HintLabel,
}

/// The type of hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HintLabel {
    /// Hint I: control-flow convergence, 1-byte displacement. Prior 1/255.
    CtrlConvRel,
    /// Hint I: control-flow convergence, 2-byte displacement. Prior 1/65535.
    CtrlConvNear,
    /// Hint I: control-flow convergence, 4-byte displacement. Prior 1/(2^32-1).
    CtrlConvLong,

    /// Hint II: control-flow crossing, 1-byte displacement.
    CtrlCrossRel,
    /// Hint II: control-flow crossing, 2-byte displacement.
    CtrlCrossNear,
    /// Hint II: control-flow crossing, 4-byte displacement.
    CtrlCrossLong,

    /// Weak control-flow hint: branch target doesn't occlude with source. Prior ~1/n.
    CtrlWeak,

    /// Hint III: register def-use. Prior 1/16.
    RegDefUse,
}

impl HintLabel {
    /// Returns the prior probability of this hint type
    ///
    /// Calibrated against Priyadarshan et al., "Accurate Disassembly of Complex Binaries
    /// Without Use of Compiler Metadata" (ASPLOS '23), Tables 2 and 3.
    pub const fn prior(self) -> f64 {
        match self {
            Self::CtrlConvRel | Self::CtrlCrossRel => 1.0 / 32.0,
            Self::CtrlConvNear | Self::CtrlCrossNear => 1.0 / 2048.0,
            Self::CtrlConvLong | Self::CtrlCrossLong => 1.0 / 32768.0,
            Self::CtrlWeak => 1.0 / 3.5,
            Self::RegDefUse => 0.5,
        }
    }
}

/// Runs all the enabled hint extractors over the superset, returning a map of hints to their priors.
pub fn extract_all_hints(superset: &Superset) -> HashMap<HintKey, f64> {
    let mut hints = HashMap::new();
    extract_control_flow_convergence(superset, &mut hints);
    extract_weak_control_flow(superset, &mut hints);
    extract_control_flow_crossing(superset, &mut hints);
    extract_register_def_use(superset, &mut hints);
    hints
}

/// Extracts control flow convergence hints from the superset.
fn extract_control_flow_convergence(superset: &Superset, hints: &mut HashMap<HintKey, f64>) {
    // Group branches by their target address.
    let mut targets: HashMap<u64, Vec<&Instruction>> = HashMap::new();
    for insn in superset.iter_valid() {
        if !insn.is_branch() {
            continue;
        }
        let Some(target) = insn.branch_target else {
            continue;
        };
        targets.entry(target).or_default().push(insn);
    }

    // For any target with two or more converging branches, emit hints.
    for branches in targets.values().filter(|b| b.len() >= 2) {
        for branch in branches {
            let label = displacement_label_for_convergence(branch);
            let key = HintKey {
                source_addr: branch.address,
                label,
            };
            hints.insert(key, label.prior());
        }
    }
}

/// Returns the hint label for a branch instruction based on its displacement encoding width.
fn displacement_label_for_convergence(insn: &Instruction) -> HintLabel {
    match insn.size {
        2 => HintLabel::CtrlConvRel,
        3 | 4 => HintLabel::CtrlConvNear,
        _ => HintLabel::CtrlConvLong,
    }
}

/// Extracts weak control-flow hints from the superset.
fn extract_weak_control_flow(superset: &Superset, hints: &mut HashMap<HintKey, f64>) {
    for insn in superset.iter_valid().filter(|i| i.is_branch()) {
        let Some(target) = insn.branch_target else {
            continue;
        };
        let Some(target_insn) = superset.at(target) else {
            continue;
        };

        let source_end = insn.address + insn.size as u64;
        let target_end = target + target_insn.size as u64;
        let occludes = insn.address < target_end && target < source_end;
        if occludes {
            continue;
        }

        emit_hint(hints, insn.address, HintLabel::CtrlWeak);
    }
}

/// Extracts control-flow crossing hints from the superset.
fn extract_control_flow_crossing(superset: &Superset, hints: &mut HashMap<HintKey, f64>) {
    // Index: "address right after a branch source" → that branch.
    let post_branch: HashMap<u64, &Instruction> = superset
        .iter_valid()
        .filter(|insn| insn.is_branch())
        .map(|insn| (insn.address + insn.size as u64, insn))
        .collect();

    for insn in superset.iter_valid().filter(|i| i.is_branch()) {
        let Some(target) = insn.branch_target else {
            continue;
        };
        let Some(&other) = post_branch.get(&target) else {
            continue;
        };
        if other.address == insn.address {
            // A branch landing immediately past itself is degenerate.
            continue;
        }

        emit_hint(hints, insn.address, displacement_label_for_crossing(insn));
        emit_hint(hints, other.address, displacement_label_for_crossing(other));
    }
}

/// Emits a hint for the given source address and label.
fn emit_hint(hints: &mut HashMap<HintKey, f64>, source_addr: u64, label: HintLabel) {
    hints.insert(HintKey { source_addr, label }, label.prior());
}

/// Returns the hint label for a branch instruction based on its displacement encoding width.
fn displacement_label_for_crossing(insn: &Instruction) -> HintLabel {
    match insn.size {
        2 => HintLabel::CtrlCrossRel,
        3 | 4 => HintLabel::CtrlCrossNear,
        _ => HintLabel::CtrlCrossLong,
    }
}

/// Extracts register define-use hints from the superset.
fn extract_register_def_use(superset: &Superset, hints: &mut HashMap<HintKey, f64>) {
    const MAX_WALK_DEPTH: usize = 50;

    for def in superset.iter_valid() {
        for &reg in &def.regs_write {
            walk_forward_for_use(superset, def.address, reg, MAX_WALK_DEPTH, hints);
        }
    }
}

/// Walks forward through the CFG to find a use of the given register before any other instruction overwrites it.
fn walk_forward_for_use(
    superset: &Superset,
    def_addr: u64,
    reg: u16,
    depth: usize,
    hints: &mut HashMap<HintKey, f64>,
) {
    let mut visited: HashSet<u64> = HashSet::new();
    let mut stack: Vec<(u64, usize)> = superset
        .successors_of(def_addr)
        .into_iter()
        .map(|s| (s, depth))
        .collect();

    while let Some((addr, remaining)) = stack.pop() {
        if remaining == 0 || !visited.insert(addr) {
            continue;
        }
        let Some(insn) = superset.at(addr) else {
            continue;
        };

        // First check use: if this instruction reads `reg`, fire the hint at
        // both def and use. We then stop on this path (paper's formulation
        // pairs each def with its first use along a path).
        if insn.regs_read.contains(&reg) {
            let label = HintLabel::RegDefUse;
            emit_hint(hints, def_addr, label);
            emit_hint(hints, addr, label);
            continue;
        }

        // Kill: this instruction overwrites `reg` without reading it first.
        if insn.regs_write.contains(&reg) {
            continue;
        }

        stack.extend(
            superset
                .successors_of(addr)
                .into_iter()
                .map(|s| (s, remaining - 1)),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_control_flow_convergence_long() {
        // 0:  e9 07 00 00 00          jmp    0xc
        // 5:  90                      nop
        // 6:  e9 01 00 00 00          jmp    0xc
        // b:  90                      nop
        // c:  90                      nop

        let bytes: &[u8] = &[
            0xE9, 0x07, 0x00, 0x00, 0x00, 0x90, 0xE9, 0x01, 0x00, 0x00, 0x00, 0x90, 0x90,
        ];
        let superset = Superset::new(0x0, bytes).expect("failed to create superset");
        let hints = extract_all_hints(&superset);

        assert!(hints.contains_key(&HintKey {
            source_addr: 0x0,
            label: HintLabel::CtrlConvLong
        }));
        assert!(hints.contains_key(&HintKey {
            source_addr: 0x6,
            label: HintLabel::CtrlConvLong
        }));
    }

    #[test]
    fn test_extract_control_flow_convergence_rel() {
        // 0x0: eb 04    jmp 0x6
        // 0x2: 90       nop
        // 0x3: eb 01    jmp 0x6
        // 0x5: 90       nop
        // 0x6: 90       nop

        let bytes: &[u8] = &[0xEB, 0x04, 0x90, 0xEB, 0x01, 0x90, 0x90];
        let superset = Superset::new(0x0, bytes).expect("failed to create superset");
        let hints = extract_all_hints(&superset);

        assert!(hints.contains_key(&HintKey {
            source_addr: 0x0,
            label: HintLabel::CtrlConvRel
        }));
        assert!(hints.contains_key(&HintKey {
            source_addr: 0x3,
            label: HintLabel::CtrlConvRel
        }));
    }

    #[test]
    // I dont like this test in the slightest. Honestly might be a hint that things arent right.
    fn test_extract_control_flow_convergence_near() {
        // 0x0: 66 74 05   data16 je 0x8
        // 0x3: 90         nop
        // 0x4: 66 74 01   data16 je 0x8
        // 0x7: 90         nop
        // 0x8: 90         nop

        let bytes: &[u8] = &[0x66, 0x74, 0x05, 0x90, 0x66, 0x74, 0x01, 0x90, 0x90];
        let superset = Superset::new(0x0, bytes).expect("failed to create superset");
        let hints = extract_all_hints(&superset);

        assert!(hints.contains_key(&HintKey {
            source_addr: 0x0,
            label: HintLabel::CtrlConvNear
        }));
        assert!(hints.contains_key(&HintKey {
            source_addr: 0x4,
            label: HintLabel::CtrlConvNear
        }));
    }

    #[test]
    fn test_extract_weak_control_flow() {
        // 0x0: e9 01 00 00 00   jmp 0x6
        // 0x5: 90               nop
        // 0x6: 90               nop

        let bytes: &[u8] = &[0xE9, 0x01, 0x00, 0x00, 0x00, 0x90, 0x90];
        let superset = Superset::new(0x0, bytes).expect("failed to create superset");
        let hints = extract_all_hints(&superset);

        assert!(hints.contains_key(&HintKey {
            source_addr: 0x0,
            label: HintLabel::CtrlWeak
        }));
    }

    #[test]
    fn test_extract_control_flow_crossing_long() {
        // 0x0: e9 05 00 00 00   jmp 0xa  <- targets end of next branch
        // 0x5: e9 00 00 00 00   jmp 0xa  <- ends at 0xa
        // 0xa: 90               nop

        let bytes: &[u8] = &[
            0xE9, 0x05, 0x00, 0x00, 0x00, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x90,
        ];
        let superset = Superset::new(0x0, bytes).expect("failed to create superset");
        let hints = extract_all_hints(&superset);

        assert!(hints.contains_key(&HintKey {
            source_addr: 0x0,
            label: HintLabel::CtrlCrossLong
        }));
        assert!(hints.contains_key(&HintKey {
            source_addr: 0x5,
            label: HintLabel::CtrlCrossLong
        }));
    }

    #[test]
    fn test_extract_control_flow_crossing_rel() {
        // 0x0: eb 02   jmp 0x4  <- targets end of next branch
        // 0x2: eb 00   jmp 0x4  <- ends at 0x4
        // 0x4: 90      nop

        let bytes: &[u8] = &[0xEB, 0x02, 0xEB, 0x00, 0x90];
        let superset = Superset::new(0x0, bytes).expect("failed to create superset");
        let hints = extract_all_hints(&superset);

        assert!(hints.contains_key(&HintKey {
            source_addr: 0x0,
            label: HintLabel::CtrlCrossRel
        }));
        assert!(hints.contains_key(&HintKey {
            source_addr: 0x2,
            label: HintLabel::CtrlCrossRel
        }));
    }

    #[test]
    fn test_extract_control_flow_crossing_near() {
        // 0x0: 66 74 00   data16 je 0x3  <- target lands at start of next branch
        // 0x3: 66 74 00   data16 je 0x6
        // 0x6: 90         nop

        let bytes: &[u8] = &[0x66, 0x74, 0x00, 0x66, 0x74, 0x00, 0x90];
        let superset = Superset::new(0x0, bytes).expect("failed to create superset");
        let hints = extract_all_hints(&superset);

        assert!(hints.contains_key(&HintKey {
            source_addr: 0x0,
            label: HintLabel::CtrlCrossNear
        }));
        assert!(hints.contains_key(&HintKey {
            source_addr: 0x3,
            label: HintLabel::CtrlCrossNear
        }));
    }

    #[test]
    fn test_extract_register_def_use() {
        // 0x0: b8 01 00 00 00   mov eax, 0x1  <- writes eax
        // 0x5: 03 d8            add ebx, eax  <- reads eax

        let bytes: &[u8] = &[0xB8, 0x01, 0x00, 0x00, 0x00, 0x03, 0xD8];
        let superset = Superset::new(0x0, bytes).expect("failed to create superset");
        let hints = extract_all_hints(&superset);

        assert!(hints.contains_key(&HintKey {
            source_addr: 0x0,
            label: HintLabel::RegDefUse
        }));
        assert!(hints.contains_key(&HintKey {
            source_addr: 0x5,
            label: HintLabel::RegDefUse
        }));
    }
}
