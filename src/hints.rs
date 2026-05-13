// src/hints.rs

use std::collections::{HashMap, HashSet};

use crate::superset::{Instruction, Superset};

/// A single hint: the address that produced it plus a label for the hint type.
/// One source address can produce multiple distinct hints with different priors,
/// so the (address, label) pair is what RH[i] sets contain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HintKey {
    pub source_addr: u64,
    pub label: HintLabel,
}

/// Hint categories from §III-B of Miller et al., with their derived priors
/// under uniform-random-bytes.
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
    CtrlCrossNear,
    CtrlCrossLong,

    /// Weak control-flow hint: branch target doesn't occlude with source. Prior ~1/n.
    CtrlWeak,

    /// Hint III: register def-use. Prior 1/16.
    RegDefUse,
}

impl HintLabel {
    pub fn prior(self) -> f64 {
        match self {
            HintLabel::CtrlConvRel | HintLabel::CtrlCrossRel => 1.0 / 255.0,
            HintLabel::CtrlConvNear | HintLabel::CtrlCrossNear => 1.0 / 65535.0,
            HintLabel::CtrlConvLong | HintLabel::CtrlCrossLong => {
                1.0 / ((1u64 << 32) as f64 - 1.0)
            }
            HintLabel::CtrlWeak => 1.0 / 3.5,
            HintLabel::RegDefUse => 1.0 / 16.0,
        }
    }
}

/// Run all enabled hint extractors over the superset.
///
/// Returns a map from each hint to its prior probability.
pub fn extract_all_hints(superset: &Superset) -> HashMap<HintKey, f64> {
    let mut hints = HashMap::new();
    extract_control_flow_convergence(superset, &mut hints);
    extract_weak_control_flow(superset, &mut hints);
    extract_control_flow_crossing(superset, &mut hints);
    extract_register_def_use(superset, &mut hints);
    hints
}

fn is_branch(insn: &Instruction) -> bool {
    use capstone::InsnGroupType;
    insn.groups.iter().any(|&g| {
        let g = g as u32;
        g == InsnGroupType::CS_GRP_JUMP || g == InsnGroupType::CS_GRP_CALL
    })
}

/// Hint I: Control Flow Convergence (§III-B).
///
/// Two valid control transfers (jumps or calls) with the same constant target.
/// Each contributing source emits a hint with prior 1/255, 1/65535, or
/// 1/(2^32-1) depending on its displacement width.
fn extract_control_flow_convergence(
    superset: &Superset,
    hints: &mut HashMap<HintKey, f64>,
) {
    // Group branches by their target address.
    let mut targets: HashMap<u64, Vec<&Instruction>> = HashMap::new();
    for insn in superset.iter_valid() {
        let target = match insn.branch_target {
            Some(t) => t,
            None => continue, // indirect branches: no static target
        };
        if !is_branch(insn) {
            continue;
        }
        targets.entry(target).or_default().push(insn);
    }

    // For any target with two or more converging branches, emit hints.
    for branches in targets.values() {
        if branches.len() < 2 {
            continue;
        }
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

/// Pick the convergence-hint label for a branch instruction based on its
/// displacement encoding width. We use the total instruction size as a proxy:
/// 2 bytes → 1-byte displacement (short rel), 5+ bytes → 4-byte displacement
/// (near/long), in-between → 2-byte displacement.
///
/// This is a heuristic. A more accurate approach would parse the operand
/// encoding, but capstone doesn't expose this directly in a portable way.
fn displacement_label_for_convergence(insn: &Instruction) -> HintLabel {
    match insn.size {
        2 => HintLabel::CtrlConvRel,
        3 | 4 => HintLabel::CtrlConvNear,
        _ => HintLabel::CtrlConvLong,
    }
}

/// Weak control-flow hint: a direct branch whose target decodes to a valid
/// instruction that doesn't overlap the source instruction's bytes.
fn extract_weak_control_flow(superset: &Superset, hints: &mut HashMap<HintKey, f64>) {
    for insn in superset.iter_valid() {
        let target = match insn.branch_target {
            Some(t) => t,
            None => continue,
        };
        if !is_branch(insn) {
            continue;
        }

        let target_insn = match superset.at(target) {
            Some(t) => t,
            None => continue,
        };

        let source_end = insn.address + insn.size as u64;
        let target_end = target + target_insn.size as u64;
        let occludes = insn.address < target_end && target < source_end;
        if occludes {
            continue;
        }

        hints.insert(
            HintKey {
                source_addr: insn.address,
                label: HintLabel::CtrlWeak,
            },
            HintLabel::CtrlWeak.prior(),
        );
    }
}

/// Hint II: control-flow crossing. Branch A's target lands at the instruction
/// immediately following some other branch B's source. Emits a hint at both.
fn extract_control_flow_crossing(superset: &Superset, hints: &mut HashMap<HintKey, f64>) {
    // Index: "address right after a branch source" → that branch.
    let mut post_branch: HashMap<u64, &Instruction> = HashMap::new();
    for insn in superset.iter_valid() {
        if !is_branch(insn) {
            continue;
        }
        let next = insn.address + insn.size as u64;
        post_branch.insert(next, insn);
    }

    for insn in superset.iter_valid() {
        let target = match insn.branch_target {
            Some(t) => t,
            None => continue,
        };
        if !is_branch(insn) {
            continue;
        }

        if let Some(other) = post_branch.get(&target) {
            if other.address == insn.address {
                continue; // a branch landing immediately past itself is degenerate
            }
            let label_a = displacement_label_for_crossing(insn);
            let label_b = displacement_label_for_crossing(other);
            hints.insert(
                HintKey { source_addr: insn.address, label: label_a },
                label_a.prior(),
            );
            hints.insert(
                HintKey { source_addr: other.address, label: label_b },
                label_b.prior(),
            );
        }
    }
}

fn displacement_label_for_crossing(insn: &Instruction) -> HintLabel {
    match insn.size {
        2 => HintLabel::CtrlCrossRel,
        3 | 4 => HintLabel::CtrlCrossNear,
        _ => HintLabel::CtrlCrossLong,
    }
}

/// Hint III: register define-use. For each instruction that writes register r,
/// walk forward through the CFG looking for an instruction that reads r before
/// any other instruction overwrites r. On finding a use, emit a hint at both
/// the def site and the use site.
fn extract_register_def_use(superset: &Superset, hints: &mut HashMap<HintKey, f64>) {
    const MAX_WALK_DEPTH: usize = 50;

    for def in superset.iter_valid() {
        if def.regs_write.is_empty() {
            continue;
        }
        for &reg in &def.regs_write {
            walk_forward_for_use(superset, def.address, reg, MAX_WALK_DEPTH, hints);
        }
    }
}

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
        let insn = match superset.at(addr) {
            Some(i) => i,
            None => continue,
        };

        // First check use: if this instruction reads `reg`, fire the hint at
        // both def and use. We then stop on this path (paper's formulation
        // pairs each def with its first use along a path).
        if insn.regs_read.contains(&reg) {
            hints.insert(
                HintKey { source_addr: def_addr, label: HintLabel::RegDefUse },
                HintLabel::RegDefUse.prior(),
            );
            hints.insert(
                HintKey { source_addr: addr, label: HintLabel::RegDefUse },
                HintLabel::RegDefUse.prior(),
            );
            continue;
        }

        // Kill: this instruction overwrites `reg` without reading it first.
        if insn.regs_write.contains(&reg) {
            continue;
        }

        for s in superset.successors_of(addr) {
            stack.push((s, remaining - 1));
        }
    }
}
