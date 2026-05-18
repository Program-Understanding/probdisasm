//! Algorithm 1: fixpoint propagation of hints, occlusion competition,
//! and posterior normalization.

use std::collections::{HashMap, HashSet};

use crate::hints::HintKey;
use crate::superset::Superset;

/// Represents the probability that a byte is data or unknown.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DataProb {
    /// The byte is definitely data.
    DefinitelyData,
    /// The byte is estimated to be data with a given probability.
    Estimated(f64),
    /// The byte is unknown.
    Unknown,
}


/// Represents the analysis of a superset, including data byte probabilities and reaching hints.
pub struct Analysis<'a> {
    superset: &'a Superset,
    data_byte: Vec<DataProb>,
    reaching_hints: HashMap<u64, HashSet<HintKey>>,
    posterior: HashMap<u64, f64>,
}

impl<'a> Analysis<'a> {
    /// Initializes a new `Analysis` with the given superset, setting up data byte probabilities and reaching hints.
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

    /// Runs the analysis algorithm to fixpoint and compute posterior probabilities.
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

    /// Builds a map of predecessors for each address in the superset.
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

    /// Propagates hints forward along control flow, merging them into reaching hints and recomputing data probabilities.
    fn propagate_hints_forward(&mut self, hint_priors: &HashMap<HintKey, f64>) -> bool {
        let hints_by_source = group_hints_by_source(hint_priors);

        let mut changed = false;
        for offset in 0..self.superset.instructions.len() {
            if self.data_byte[offset] == DataProb::DefinitelyData {
                continue;
            }
            let addr = self.superset.base_addr + offset as u64;
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

    /// Propagates data probabilities backward through the occlusion space, updating `data_byte` and `posterior`.
    fn propagate_to_occlusion_space(&mut self) -> bool {
        let mut changed = false;

        for offset in 0..self.superset.instructions.len() {
            if self.data_byte[offset] != DataProb::Unknown {
                continue;
            }

            let addr = self.superset.base_addr + offset as u64;
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

                let peer_prob = min_log_prob.exp();
                let one_minus_peer = (1.0 - peer_prob).max(f64::MIN_POSITIVE);
                let new_log_prob = one_minus_peer.ln();
                self.data_byte[offset] = DataProb::Estimated(new_log_prob);
                changed = true;
            }
        }
        changed
    }

    /// Propagates invalidity backward through the instruction set, updating `data_byte`.
    fn propagate_invalidity_backward(&mut self, predecessors: &HashMap<u64, Vec<u64>>) -> bool {
        let mut changed = false;
        let empty: Vec<u64> = Vec::new();

        for offset in (0..self.superset.instructions.len()).rev() {
            let addr = self.superset.base_addr + offset as u64;

            let d_i = match self.data_byte[offset] {
                DataProb::Estimated(lp) => lp,
                DataProb::DefinitelyData => 0.0, // log(1.0)
                DataProb::Unknown => continue,
            };

            for &p in predecessors.get(&addr).unwrap_or(&empty) {
                let p_offset = match p.checked_sub(self.superset.base_addr) {
                    Some(o) => o as usize,
                    None => continue,
                };
                if p_offset >= self.data_byte.len() {
                    continue;
                }

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

    /// Normalizes the data byte probabilities to posterior probabilities in the range [0, 1].
    fn normalize(&mut self) {
        for offset in 0..self.superset.instructions.len() {
            let addr = self.superset.base_addr + offset as u64;
            let log_data_prob = match self.data_byte[offset] {
                DataProb::DefinitelyData => {
                    self.posterior.insert(addr, 0.0);
                    continue;
                }
                DataProb::Estimated(log_prob) => log_prob,
                DataProb::Unknown => continue,
            };

            let mut neg_log_data_probs: Vec<f64> = Vec::new();
            neg_log_data_probs.push(-log_data_prob);

            for peer_addr in self.occluding_addrs(addr) {
                let Some(peer_offset) = self.offset_of(peer_addr) else {
                    continue;
                };
                match self.data_byte[peer_offset] {
                    DataProb::Estimated(log_prob) => neg_log_data_probs.push(-log_prob),
                    DataProb::DefinitelyData => neg_log_data_probs.push(0.0),
                    DataProb::Unknown => {}
                }
            }

            let max_term = neg_log_data_probs
                .iter()
                .copied()
                .fold(f64::NEG_INFINITY, f64::max);

            if !max_term.is_finite() {
                // All terms underflowed to -inf cant compute a worth while posterior
                continue;
            }

            let shifted_sum: f64 = neg_log_data_probs
                .iter()
                .map(|x| (x - max_term).exp())
                .sum();

            let log_total = max_term + shifted_sum.ln();

            let posterior = (-log_data_prob - log_total).exp().clamp(0.0, 1.0);
            self.posterior.insert(addr, posterior);
        }
    }

    // ---- Helpers ----

    /// Returns the successors of the given address
    fn successors_of(&self, addr: u64) -> Vec<u64> {
        self.superset.successors_of(addr)
    }

    /// Returns the offset of an address
    fn offset_of(&self, addr: u64) -> Option<usize> {
        let offset = addr.checked_sub(self.superset.base_addr)? as usize;
        (offset < self.data_byte.len()).then_some(offset)
    }

    /// Returns the occluding address of an address
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

    /// Returns the sorted posterior probabilities and addresses.
    pub fn sorted_posteriors(&self) -> Vec<(u64, f64)> {
        let mut out: Vec<(u64, f64)> = self.posterior.iter().map(|(&a, &p)| (a, p)).collect();
        out.sort_by_key(|(addr, _)| *addr);
        out
    }

    /// Merges reaching hints for the given address.
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

/// Computes the log product of the reaching hints and their priors.
fn log_product(rh: &HashSet<HintKey>, hint_priors: &HashMap<HintKey, f64>) -> f64 {
    rh.iter()
        .filter_map(|h| hint_priors.get(h))
        .map(|p| p.ln())
        .sum()
}

/// Groups hints by their source address.
fn group_hints_by_source(hint_priors: &HashMap<HintKey, f64>) -> HashMap<u64, Vec<HintKey>> {
    let mut by_source: HashMap<u64, Vec<HintKey>> = HashMap::new();
    for &k in hint_priors.keys() {
        by_source.entry(k.source_addr).or_default().push(k);
    }
    by_source
}
