use std::collections::{HashMap, HashSet};

use crate::hints::HintKey;
use crate::superset::Superset;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DataProb {
    DefinitelyData,
    Estimated(f64),
    Unknown,
}

pub struct Analysis<'a> {
    superset: &'a Superset,
    data_byte: Vec<DataProb>,
    reaching_hints: HashMap<u64, HashSet<HintKey>>,
    posterior: HashMap<u64, f64>,
}

impl<'a> Analysis<'a> {
    /// Algorithm 1 lines 1-6: initialize D[i] and RH[i] for every address in B.
    pub fn new(superset: &'a Superset) -> Self {
        let data_byte = superset
            .instructions
            .iter()
            // This pattern is so sick.
            .map(|insn| match insn {
                Some(_) => DataProb::Unknown,
                None => DataProb::DefinitelyData,
            })
            .collect();

        Self {
            superset,
            data_byte,
            reaching_hints: HashMap::new(),
            posterior: HashMap::new(),
        }
    }

    /// Run Algorithm 1 to fixpoint and compute posterior probabilities.
    pub fn run(&mut self, hint_priors: &HashMap<HintKey, f64>) {
        const MAX_ITER: usize = 100;
        let predecessors = self.build_predecessor_map();
        for _ in 0..MAX_ITER {
            let forward = self.propagate_hints_forward(hint_priors);
            let occlusion = self.propagate_to_occlusion_space();
            let backward = self.propagate_invalidity_backward(&predecessors);
            if !forward && !occlusion && !backward {
                break;
            }
        }
        self.normalize();
    }

    /// Precompute reverse CFG edges so computation is quicker.
    fn build_predecessor_map(&self) -> HashMap<u64, Vec<u64>> {
        let mut map: HashMap<u64, Vec<u64>> = HashMap::new();
        for offset in 0..self.superset.instructions.len() {
            let addr = self.superset.base_addr + offset as u64;
            for succ in self.successors_of(addr) {
                map.entry(succ).or_default().push(addr);
            }
        }
        map
    }
    ///
    ///for each address i from start of B to end do
    // 11: if D[i] ≡1.0 then
    // 12: continue
    // 13: if H[i] ̸= ⊥and i ̸∈RH[i] then
    // 14: RH[i] ←RH[i] ∪{i}
    // 15: D[i] ←Πh∈RH[i]H[h]
    // 16: for each n, the next instruction of i along control flow do
    // 17: if RH[i]−RH[n] ̸= {}then
    // 18: RH[n] ←RH[n] ∪RH[i]
    // 19: D[n] ←Πh∈RH[n]H[h]
    // 20: if n < i then
    // 21: fixed point ←f alse
    fn propagate_hints_forward(&mut self, hint_priors: &HashMap<HintKey, f64>) -> bool {
        // Precompute source_addr → hints fired there, so we don't scan all
        // hint_priors keys for every address.
        let hints_by_source = group_hints_by_source(hint_priors);

        let mut changed = false;
        for offset in 0..self.superset.instructions.len() {
            // Lines 11-12: skip definitely-data.
            if self.data_byte[offset] == DataProb::DefinitelyData {
                continue;
            }
            let addr = self.superset.base_addr + offset as u64;

            // Lines 13-15: if this address itself is a hint source, merge those
            // hints into RH[addr] and recompute D[addr].
            if let Some(hints_fired_here) = hints_by_source.get(&addr)
                && self.merge_reaching_hints(
                    addr,
                    offset,
                    hints_fired_here.iter().copied(),
                    hint_priors,
                )
            {
                changed = true;
            }

            // Lines 16-21: propagate RH[addr] to control-flow successors.
            let reaching_here: HashSet<HintKey> =
                self.reaching_hints.get(&addr).cloned().unwrap_or_default();
            if reaching_here.is_empty() {
                continue;
            }
            for succ_addr in self.successors_of(addr) {
                let Some(succ_offset) = self.offset_of(succ_addr) else {
                    continue;
                };
                if self.data_byte[succ_offset] == DataProb::DefinitelyData {
                    continue;
                }
                if self.merge_reaching_hints(
                    succ_addr,
                    succ_offset,
                    reaching_here.iter().copied(),
                    hint_priors,
                ) {
                    changed = true;
                }
            }
        }
        changed
    }

    fn propagate_to_occlusion_space(&mut self) -> bool {
        let mut changed = false;

        for offset in 0..self.superset.instructions.len() {
            // Line 23: only update addresses currently ⊥.
            if self.data_byte[offset] != DataProb::Unknown {
                continue;
            }

            let addr = self.superset.base_addr + offset as u64;

            // Find min log(D[j]) over occluding peers j with known D values.
            // Algorithm 1 line 24: D[i] = 1 - min_j(D[j]).
            // In log-space: log(1 - exp(min_log_d_j)).
            let mut min_log_prob: Option<f64> = None;
            for peer_addr in self.occluding_addrs(addr) {
                let Some(peer_offset) = self.offset_of(peer_addr) else {
                    continue;
                };
                let peer_log_prob = match self.data_byte[peer_offset] {
                    DataProb::Estimated(log_prob) => log_prob,
                    DataProb::DefinitelyData => 0.0,
                    DataProb::Unknown => continue,
                };
                min_log_prob = Some(match min_log_prob {
                    None => peer_log_prob,
                    Some(running_min) => running_min.min(peer_log_prob),
                });
            }
            if let Some(min_log_prob) = min_log_prob {
                // D[i] = 1 - exp(min_log_prob). Convert back to log space.
                // log1p(-exp(m)) = log(1 - exp(m)), numerically stable for small exp(m).
                let peer_prob = min_log_prob.exp();
                // Guard against numerical edge cases.
                let one_minus_peer = (1.0 - peer_prob).max(f64::MIN_POSITIVE);
                let new_log_prob = one_minus_peer.ln();
                self.data_byte[offset] = DataProb::Estimated(new_log_prob);
                changed = true;
            }
        }
        changed
    }

    fn propagate_invalidity_backward(&mut self, predecessors: &HashMap<u64, Vec<u64>>) -> bool {
        let mut changed = false;
        let empty: Vec<u64> = Vec::new();

        // Walk addresses end → start (line 25).
        for offset in (0..self.superset.instructions.len()).rev() {
            let addr = self.superset.base_addr + offset as u64;

            let d_i = match self.data_byte[offset] {
                DataProb::Estimated(lp) => lp,
                DataProb::DefinitelyData => 0.0, // log(1.0)
                DataProb::Unknown => continue,   // can't propagate from ⊥
            };

            // For each predecessor p of i (line 26).
            for &p in predecessors.get(&addr).unwrap_or(&empty) {
                let p_offset = match p.checked_sub(self.superset.base_addr) {
                    Some(o) => o as usize,
                    None => continue,
                };
                if p_offset >= self.data_byte.len() {
                    continue;
                }

                // Lines 27-28: if D[p] is ⊥ or D[p] < D[i], lift D[p] to D[i].
                let should_update = match self.data_byte[p_offset] {
                    DataProb::Unknown => true,
                    DataProb::Estimated(lp) => lp < d_i,
                    DataProb::DefinitelyData => false, // already maxed
                };

                if should_update {
                    self.data_byte[p_offset] = if d_i == 0.0 {
                        DataProb::DefinitelyData
                    } else {
                        DataProb::Estimated(d_i)
                    };
                    changed = true;
                }
            }
        }

        changed
    }

    fn normalize(&mut self) {
        // Algorithm 1 lines 31-38: compute P[i] for every address.
        //
        //   if D[i] = 1.0:        P[i] = 0
        //   else:                 s = 1/D[i]
        //                         for j occluded with i: s += 1/D[j]
        //                         P[i] = (1/D[i]) / s
        //
        // We work in log space throughout. Let li = log(D[i]). Then 1/D[i] = exp(-li).
        // To avoid underflow when computing sum of exp(-li) + exp(-lj) + ..., we use
        // the log-sum-exp trick: shift by the max so the largest term is exp(0) = 1.

        for offset in 0..self.superset.instructions.len() {
            let addr = self.superset.base_addr + offset as u64;

            // Lines 32-34: if D[i] = 1.0 (definitely data), P[i] = 0.
            let log_data_prob = match self.data_byte[offset] {
                DataProb::DefinitelyData => {
                    self.posterior.insert(addr, 0.0);
                    continue;
                }
                DataProb::Estimated(log_prob) => log_prob,
                DataProb::Unknown => continue,
            };

            // Gather -log(D[k]) for i and each occluding peer with a known D.
            // (1/D = exp(-log D), so we accumulate the negated log-densities.)
            let mut neg_log_data_probs: Vec<f64> = Vec::new();
            neg_log_data_probs.push(-log_data_prob);

            for peer_addr in self.occluding_addrs(addr) {
                let Some(peer_offset) = self.offset_of(peer_addr) else {
                    continue;
                };
                match self.data_byte[peer_offset] {
                    DataProb::Estimated(log_prob) => neg_log_data_probs.push(-log_prob),
                    DataProb::DefinitelyData => neg_log_data_probs.push(0.0), // -log(1.0)
                    DataProb::Unknown => {}                                   // contributes nothing
                }
            }

            let max_term = neg_log_data_probs
                .iter()
                .copied()
                .fold(f64::NEG_INFINITY, f64::max);

            if !max_term.is_finite() {
                // All terms underflowed to -inf; can't compute a meaningful posterior.
                continue;
            }

            let shifted_sum: f64 = neg_log_data_probs
                .iter()
                .map(|x| (x - max_term).exp())
                .sum();

            let log_total = max_term + shifted_sum.ln();

            // P[i] = (1/D[i]) / s = exp(-log_data_prob - log_total)
            let posterior = (-log_data_prob - log_total).exp().clamp(0.0, 1.0);
            self.posterior.insert(addr, posterior);
        }
    }

    // ---- Helpers ----
    fn successors_of(&self, addr: u64) -> Vec<u64> {
        self.superset.successors_of(addr)
    }

    fn offset_of(&self, addr: u64) -> Option<usize> {
        let offset = addr.checked_sub(self.superset.base_addr)? as usize;
        (offset < self.data_byte.len()).then_some(offset)
    }

    /// Addresses whose decoded instruction overlaps `addr`'s bytes.
    /// Two instructions [a, a+sa) and [b, b+sb) overlap iff a < b+sb and b < a+sa.
    fn occluding_addrs(&self, addr: u64) -> Vec<u64> {
        let i = match self.superset.at(addr) {
            Some(i) => i,
            None => return Vec::new(),
        };
        let i_end = addr + i.size as u64;
        let max_size = 15; // x86 max instruction length

        let mut out = Vec::new();
        let scan_start = addr.saturating_sub(max_size - 1);
        let scan_end = i_end + max_size - 1;

        let mut a = scan_start;
        while a < scan_end {
            if a == addr {
                a += 1;
                continue;
            }
            if let Some(j) = self.superset.at(a) {
                let j_end = a + j.size as u64;
                if a < i_end && addr < j_end {
                    out.push(a);
                }
            }
            a += 1;
        }
        out
    }

    pub fn sorted_posteriors(&self) -> Vec<(u64, f64)> {
        let mut out: Vec<(u64, f64)> = self.posterior.iter().map(|(&a, &p)| (a, p)).collect();
        out.sort_by_key(|(addr, _)| *addr);
        out
    }

    fn merge_reaching_hints(
        &mut self,
        addr: u64,
        offset: usize,
        new_hints: impl IntoIterator<Item = HintKey>,
        hint_priors: &HashMap<HintKey, f64>,
    ) -> bool {
        let reaching = self.reaching_hints.entry(addr).or_default();
        let before = reaching.len();
        reaching.extend(new_hints);
        if reaching.len() == before {
            return false;
        }
        let log_d = log_product(reaching, hint_priors);
        self.data_byte[offset] = DataProb::Estimated(log_d);
        true
    }
}

/// Compute log(D[i]) = sum of log(H[h]) over h in RH[i].
fn log_product(rh: &HashSet<HintKey>, hint_priors: &HashMap<HintKey, f64>) -> f64 {
    rh.iter()
        .filter_map(|h| hint_priors.get(h))
        .map(|p| p.ln())
        .sum()
}

fn group_hints_by_source(hint_priors: &HashMap<HintKey, f64>) -> HashMap<u64, Vec<HintKey>> {
    let mut by_source: HashMap<u64, Vec<HintKey>> = HashMap::new();
    for &k in hint_priors.keys() {
        by_source.entry(k.source_addr).or_default().push(k);
    }
    by_source
}
