pub struct Analysis {
    superset: &'a Superset,
    data_byte_log_prob: HashMap<u64, f64>,
    reasoning_hints: HashMap<u64, HashSet<u64>>,
    posterior: HashMap<u64, f64>,
}

impl<'a> Analysis<'a> {
    pub fn new(superset: &'a Superset) -> Self {
        let mut data_byte_log_prob = HashMap::new();
        let mut reasoning_hints = HashMap::new();

        for offset in 0..superset.bytes.len() {
            let addr = superset.base_addr + offset as u64;
            if superset.at(addr).is_none() {
                data_byte_log_prob.insert(addr, 0.0);
            }
            reasoning_hints.insert(addr, HashSet::new());
        }
        let mut posterior = HashMap::new();
        Self {
            superset,
            data_byte_log_prob,
            reasoning_hints,
            posterior,
        }
    }

    pub fn run(&mut self, hint_priors: &HashMap<u64, f64>) {
        const MAX_ITER: usize = 100;

        for _ in 0..MAX_ITER {
            let changed_forward = self.propogate_forward(hint_priors);
            let changed_occlusion = self.propogate_occlusion();
            let changed_backward = self.propogate_backward();
            if !changed_forward && !changed_occlusion && !changed_backward {
                break;
            }
        }
        self.normalize();
    }

    // ---- Algorithm 1 Step I: Forward propagation of hints (lines 10-21) ----

    /// For each address, if it is itself a hint, add it to its reaching-hint
    /// set and update its data-byte probability. Then propagate the reaching-hint
    /// set to control-flow successors.
    ///
    /// Returns true if any state changed (for fixpoint detection).
    fn propagate_hints_forward(&mut self, hint_priors: &HashMap<u64, f64>) -> bool {
        let _ = hint_priors;
        todo!("Step I: forward propagation of hints")
    }

    // ---- Algorithm 1 Step II: Occlusion-space propagation (lines 22-24) ----

    /// For each address with no data-byte estimate yet, if it occludes with an
    /// address that has one, set its data-byte log-prob to log(1 - min(D[j]))
    /// over occluding peers j.
    ///
    /// Returns true if any state changed.
    fn propagate_to_occlusion_space(&mut self) -> bool {
        todo!("Step II: occlusion-space propagation")
    }

    // ---- Algorithm 1 Step III: Backward invalidity propagation (lines 25-30) ----

    /// For each address i, walk to control-flow predecessors. If a predecessor
    /// has a higher data-byte log-prob than i (i.e. it's "more invalid"), or
    /// is unset and i is set, lift its log-prob up to match.
    ///
    /// Returns true if any state changed.
    fn propagate_invalidity_backward(&mut self) -> bool {
        todo!("Step III: backward invalidity propagation")
    }

    // ---- Algorithm 1 lines 31-38: Posterior normalization ----

    /// Compute the final posterior probability for each address by normalizing
    /// over its occlusion space:
    ///
    ///     posterior[i] = (1 / D[i]) / sum over j in occlusion(i) of (1 / D[j])
    ///
    /// This is what produces the per-address probabilities in [0, 1] that the
    /// paper reports (e.g. 0.94, 0.04, 0.695 in Figure 1d).
    fn normalize(&mut self) {
        todo!("posterior normalization")
    }

    // ---- Public accessors ----

    /// Posterior probability that `addr` is a true instruction, in [0, 1].
    /// Returns None if the address has no posterior (e.g. invalid bytes).
    pub fn posterior(&self, addr: u64) -> Option<f64> {
        self.posterior.get(&addr).copied()
    }

    /// Probability that `addr` is a data byte, in [0, 1].
    /// Returns None if no estimate is available (the paper's ⊥).
    pub fn data_byte_prob(&self, addr: u64) -> Option<f64> {
        self.data_byte_log_prob.get(&addr).map(|lp| lp.exp())
    }

    /// log of the data-byte probability. Useful for debugging numerical issues.
    pub fn data_byte_log_prob(&self, addr: u64) -> Option<f64> {
        self.data_byte_log_prob.get(&addr).copied()
    }

    /// The set of hint addresses currently reaching `addr`.
    pub fn reaching_hints(&self, addr: u64) -> Option<&HashSet<u64>> {
        self.reaching_hints.get(&addr)
    }

    /// Iterator over all addresses with a computed posterior, paired with their value.
    pub fn iter_posteriors(&self) -> impl Iterator<Item = (u64, f64)> + '_ {
        self.posterior.iter().map(|(&a, &p)| (a, p))
    }
}
