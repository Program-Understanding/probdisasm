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
            .map(|insn| {
                if insn.is_none() {
                    DataProb::DefinitelyData
                } else {
                    DataProb::Unknown
                }
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
            let f = self.propagate_hints_forward(hint_priors);
            let o = self.propagate_to_occlusion_space();
            let b = self.propagate_invalidity_backward(&predecessors);
            if !f && !o && !b {
                break;
            }
        }
        self.normalize();
    }

    /// Precompute reverse CFG edges so backward propagation is O(N) per pass
    /// instead of O(N^2). Built once per `run()`.
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
        let mut changed = false;

        // Precompute: source address → hints fired at that address.
        // Avoids scanning all hint_priors keys per address.
        let mut hints_by_source: HashMap<u64, Vec<HintKey>> = HashMap::new();
        for &k in hint_priors.keys() {
            hints_by_source.entry(k.source_addr).or_default().push(k);
        }

        for offset in 0..self.superset.instructions.len() {
            // Lines 11-12: skip definitely-data.
            if self.data_byte[offset] == DataProb::DefinitelyData {
                continue;
            }

            let addr = self.superset.base_addr + offset as u64;

            // Lines 13-15: self-source case — if this address is itself a hint
            // source, add its hints to RH[i] and recompute D[i].
            if let Some(own_hints) = hints_by_source.get(&addr) {
                let rh = self.reaching_hints.entry(addr).or_default();
                let mut grew = false;
                for &h in own_hints {
                    if rh.insert(h) {
                        grew = true;
                    }
                }
                if grew {
                    let log_d = log_product(rh, hint_priors);
                    self.data_byte[offset] = DataProb::Estimated(log_d);
                    changed = true;
                }
            }

            // Lines 16-21: propagate RH[i] to control-flow successors.
            let rh_i: HashSet<HintKey> = self
                .reaching_hints
                .get(&addr)
                .cloned()
                .unwrap_or_default();

            if rh_i.is_empty() {
                continue;
            }

            for n in self.successors_of(addr) {
                let n_offset = match n.checked_sub(self.superset.base_addr) {
                    Some(o) => o as usize,
                    None => continue,
                };
                if n_offset >= self.data_byte.len() {
                    continue;
                }
                if self.data_byte[n_offset] == DataProb::DefinitelyData {
                    continue;
                }

                let rh_n = self.reaching_hints.entry(n).or_default();
                let before = rh_n.len();
                rh_n.extend(rh_i.iter().copied());
                if rh_n.len() > before {
                    let log_d = log_product(rh_n, hint_priors);
                    self.data_byte[n_offset] = DataProb::Estimated(log_d);
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
            let mut min_log_d: Option<f64> = None;
            for j in self.occluding_addrs(addr) {
                let j_offset = match j.checked_sub(self.superset.base_addr) {
                    Some(o) => o as usize,
                    None => continue,
                };
                let log_dj = match self.data_byte.get(j_offset) {
                    Some(DataProb::Estimated(lp)) => *lp,
                    Some(DataProb::DefinitelyData) => 0.0,
                    _ => continue, // Unknown or out of range
                };
                min_log_d = Some(match min_log_d {
                    None => log_dj,
                    Some(cur) => cur.min(log_dj),
                });
            }

            if let Some(m) = min_log_d {
                // D[i] = 1 - exp(m). Convert back to log space.
                // log1p(-exp(m)) = log(1 - exp(m)), numerically stable for small exp(m).
                let dj = m.exp();
                // Guard against numerical edge cases.
                let one_minus_dj = (1.0 - dj).max(f64::MIN_POSITIVE);
                let new_log_d = one_minus_dj.ln();

                self.data_byte[offset] = DataProb::Estimated(new_log_d);
                changed = true;
            }
        }

        changed
    }

    fn propagate_invalidity_backward(
        &mut self,
        predecessors: &HashMap<u64, Vec<u64>>,
    ) -> bool {
        let mut changed = false;
        let empty: Vec<u64> = Vec::new();

        // Walk addresses end → start (line 25).
        for offset in (0..self.superset.instructions.len()).rev() {
            let addr = self.superset.base_addr + offset as u64;

            let d_i = match self.data_byte[offset] {
                DataProb::Estimated(lp) => lp,
                DataProb::DefinitelyData => 0.0, // log(1.0)
                DataProb::Unknown => continue,    // can't propagate from ⊥
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
                    // Line 29: implicit — by setting `changed`, we trigger another
                    // fixpoint iteration regardless of p's address vs i's.
                }
            }
        }

        changed
    }

    // ---- Helpers ----

    /// Compute log(D[i]) = sum of log(H[h]) over h in RH[i].
    fn log_product(rh: &HashSet<HintKey>, hint_priors: &HashMap<HintKey, f64>) -> f64 {
        rh.iter()
            .filter_map(|h| hint_priors.get(h))
            .map(|p| p.ln())
            .sum()
    }

    fn successors_of(&self, addr: u64) -> Vec<u64> {
        self.superset.successors_of(addr)
    }

    /// Addresses whose decoded instruction overlaps `addr`'s bytes.
    /// Two instructions [a, a+sa) and [b, b+sb) overlap iff a < b+sb and b < a+sa.
    fn occluding_addrs(&self, addr: u64) -> Vec<u64> {
        let i = match self.superset.at(addr) {
            Some(i) => i,
            None => return Vec::new(),
        };
        let i_end = addr + i.size as u64;
        let max_size = 15u64; // x86 max instruction length

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
            let log_d_i = match self.data_byte[offset] {
                DataProb::DefinitelyData => {
                    self.posterior.insert(addr, 0.0);
                    continue;
                }
                DataProb::Estimated(lp) => lp,
                DataProb::Unknown => {
                    // No estimate at all: the algorithm doesn't define P[i] here.
                    // We skip rather than emit a posterior.
                    continue;
                }
            };

            // Collect log(D[j]) for i and its occlusion peers, gathering -log(D)
            // values (since the formula uses 1/D, and 1/D = exp(-log(D))).
            let mut neg_log_ds: Vec<f64> = Vec::with_capacity(8);
            neg_log_ds.push(-log_d_i);

            for j in self.occluding_addrs(addr) {
                let j_offset = match j.checked_sub(self.superset.base_addr) {
                    Some(o) => o as usize,
                    None => continue,
                };
                let log_d_j = match self.data_byte.get(j_offset) {
                    Some(DataProb::Estimated(lp)) => *lp,
                    Some(DataProb::DefinitelyData) => 0.0,
                    _ => continue, // Unknown peers don't contribute
                };
                neg_log_ds.push(-log_d_j);
            }

            // log-sum-exp: log(sum(exp(x_k))) = max + log(sum(exp(x_k - max)))
            let max = neg_log_ds.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
            let log_s = if max.is_finite() {
                let shifted_sum: f64 = neg_log_ds.iter().map(|x| (x - max).exp()).sum();
                max + shifted_sum.ln()
            } else {
                // All terms underflowed to -inf; can't compute a meaningful posterior.
                continue;
            };

            // P[i] = (1/D[i]) / s = exp(-log_d_i) / exp(log_s) = exp(-log_d_i - log_s)
            let log_p = -log_d_i - log_s;
            let p = log_p.exp();

            // Numerical guard: posterior must be in [0, 1]. Clamp tiny negatives or
            // values that exceed 1 due to floating-point drift.
            let p = p.max(0.0).min(1.0);

            self.posterior.insert(addr, p);
        }
    }

    pub fn posteriors(&self) -> &HashMap<u64, f64> {
        &self.posterior
    }
}

/// Compute log(D[i]) = sum of log(H[h]) over h in RH[i].
fn log_product(rh: &HashSet<HintKey>, hint_priors: &HashMap<HintKey, f64>) -> f64 {
    rh.iter()
        .filter_map(|h| hint_priors.get(h))
        .map(|p| p.ln())
        .sum()
}
