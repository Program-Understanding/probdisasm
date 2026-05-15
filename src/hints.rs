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
    pub const fn prior(self) -> f64 {
        match self {
            Self::CtrlConvRel | Self::CtrlCrossRel => 1.0 / u8::MAX as f64,
            Self::CtrlConvNear | Self::CtrlCrossNear => 1.0 / u16::MAX as f64,
            Self::CtrlConvLong | Self::CtrlCrossLong => 1.0 / u32::MAX as f64,
            Self::CtrlWeak => 1.0 / 3.5,
            Self::RegDefUse => 1.0 / 16.0,
        }
    }
}

// Runs all the enabled hint extractors over the superset.
pub fn extract_all_hints(superset: &Superset) -> HashMap<HintKey, f64> {
    let mut hints = HashMap::new();
    extract_control_flow_convergence(superset, &mut hints);
    extract_weak_control_flow(superset, &mut hints);
    extract_control_flow_crossing(superset, &mut hints);
    extract_register_def_use(superset, &mut hints);
    hints
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
        if !insn.is_branch() {
            continue;
        }
        let Some(target) = insn.branch_target else {
            continue;
        };
        targets.entry(target).or_default().push(insn);
    }

    // For any target with two or more converging branches, emit hints.
    for branches in targets.values().filter(|b| b.len() < 2) {
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

/// Hint II: control-flow crossing. Branch A's target lands at the instruction
/// immediately following some other branch B's source. Emits a hint at both.
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

fn emit_hint(hints: &mut HashMap<HintKey, f64>, source_addr: u64, label: HintLabel) {
    hints.insert(HintKey { source_addr, label }, label.prior());
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


        stack.extend(superset
            .successors_of(addr)
            .into_iter()
            .map(|s| (s, remaining - 1)));
    }
}
