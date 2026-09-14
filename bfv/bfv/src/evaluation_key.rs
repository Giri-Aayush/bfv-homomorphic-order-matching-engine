use crate::{rot_to_galois_element, BfvParameters, GaloisKey, RelinearizationKey, SecretKey};
use itertools::{izip, Itertools};
use rand::{CryptoRng, RngCore};
use std::collections::HashMap;

#[derive(Debug, PartialEq)]
pub struct EvaluationKey {
    pub(crate) rlks: HashMap<usize, RelinearizationKey>,
    pub(crate) rtgs: HashMap<(isize, usize), GaloisKey>,
}

impl EvaluationKey {
    /// An evaluation key assembled from keys generated elsewhere. `rtgs` are keyed by the
    /// rotation index passed to `Evaluator::rotate`, as `new` does.
    pub fn from_parts(rlks: Vec<(usize, RelinearizationKey)>, rtgs: Vec<((isize, usize), GaloisKey)>) -> EvaluationKey {
        EvaluationKey { rlks: rlks.into_iter().collect(), rtgs: rtgs.into_iter().collect() }
    }

    pub fn new<R: CryptoRng + RngCore>(
        params: &BfvParameters,
        sk: &SecretKey,
        rlk_levels: &[usize],
        rtg_levels: &[usize],
        rtg_indices: &[isize],
        rng: &mut R,
    ) -> EvaluationKey {
        assert!(rtg_levels.len() == rtg_indices.len());

        let mut rlks = HashMap::new();
        rlk_levels.iter().for_each(|l| {
            rlks.insert(*l, RelinearizationKey::new(params, sk, *l, rng));
        });

        let mut rtgs = HashMap::new();
        izip!(rtg_indices.iter(), rtg_levels.iter()).for_each(|(index, level)| {
            let el = {
                if *index == (2 * params.degree - 1) as isize {
                    2 * params.degree - 1
                } else {
                    rot_to_galois_element(*index, params.degree)
                }
            };
            rtgs.insert(
                (*index, *level),
                GaloisKey::new(el, params, *level, sk, rng),
            );
        });

        EvaluationKey { rlks, rtgs }
    }

    pub fn get_rtg_ref(&self, rot_by: isize, level: usize) -> &GaloisKey {
        self.rtgs.get(&(rot_by, level)).expect("Rtg missing!")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
}
