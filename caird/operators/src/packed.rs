//! Several values per ciphertext, one per SIMD slot, and the row-wise primitives a packed
//! matcher needs: prefix sums, row totals broadcast to every slot, and 0/1 masks.
//!
//! BFV batching lays the n slots out as two rows of n/2. This library's Galois keys rotate
//! within a row and it has no row swap, so a "lane" here is one row and callers pack at most
//! `lane_len` values per ciphertext. The second row is carried along and ignored.

use bfv::{Ciphertext, Encoding, EvaluationKey, Evaluator, PolyCache, PolyType, Representation};

/// Usable slots per ciphertext: one row of the slot matrix.
pub fn lane_len(evaluator: &Evaluator) -> usize {
    evaluator.params().degree / 2
}

/// The rotation indices `prefix_sum` and `broadcast_sum` need keys for: right shifts by
/// 1, 2, 4, ... below the lane length. Pass these as `rtg_indices` to `EvaluationKey::new`.
pub fn rotation_indices(evaluator: &Evaluator) -> Vec<isize> {
    let lane = lane_len(evaluator);
    (0..)
        .map(|k| 1usize << k)
        .take_while(|&s| s < lane)
        .map(|s| -(s as isize))
        .collect()
}

/// Multiply slot i by `keep[i]` (0 or 1). Slots past the end of `keep` are zeroed.
/// Returns a ciphertext in coefficient representation so it composes with add and rotate.
pub fn mask(evaluator: &Evaluator, ct: &Ciphertext, keep: &[bool]) -> Ciphertext {
    let n = evaluator.params().degree;
    let m: Vec<u64> = (0..n).map(|i| keep.get(i).copied().unwrap_or(false) as u64).collect();
    let pt = evaluator.plaintext_encode(&m, Encoding::simd(ct.level(), PolyCache::Mul(PolyType::Q)));
    let mut ct = ct.clone();
    evaluator.ciphertext_change_representation(&mut ct, Representation::Evaluation);
    let mut out = evaluator.mul_plaintext(&ct, &pt);
    evaluator.ciphertext_change_representation(&mut out, Representation::Coefficient);
    out
}

/// In-row prefix sums: slot i becomes the sum of slots 0..=i of its row.
///
/// log2(lane) rounds. A right rotation by s brings slot i-s into slot i and wraps the row
/// tail into the first s slots; the mask drops that wrap before the add.
pub fn prefix_sum(evaluator: &Evaluator, ct: &Ciphertext, ek: &EvaluationKey) -> Ciphertext {
    let n = evaluator.params().degree;
    let lane = lane_len(evaluator);
    let mut acc = ct.clone();
    let mut shift = 1;
    while shift < lane {
        let rotated = evaluator.rotate(&acc, -(shift as isize), ek);
        let keep: Vec<bool> = (0..n).map(|i| i % lane >= shift).collect();
        let carried = mask(evaluator, &rotated, &keep);
        acc = evaluator.add(&acc, &carried);
        shift <<= 1;
    }
    acc
}

/// Every slot of a row becomes that row's sum. log2(lane) rotate-and-adds, no masks.
pub fn broadcast_sum(evaluator: &Evaluator, ct: &Ciphertext, ek: &EvaluationKey) -> Ciphertext {
    let lane = lane_len(evaluator);
    let mut acc = ct.clone();
    let mut shift = 1;
    while shift < lane {
        let rotated = evaluator.rotate(&acc, -(shift as isize), ek);
        acc = evaluator.add(&acc, &rotated);
        shift <<= 1;
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::univariate_less_than;
    use bfv::{BfvParameters, SecretKey};
    use rand::thread_rng;

    struct Fixture {
        evaluator: Evaluator,
        sk: SecretKey,
        ek: EvaluationKey,
        rng: rand::rngs::ThreadRng,
    }

    impl Fixture {
        fn new() -> Self {
            let mut rng = thread_rng();
            let mut params = BfvParameters::new(&[60; 10], 65537, 1 << 4);
            params.enable_hybrid_key_switching(&[60; 3]);
            let sk = SecretKey::random_with_params(&params, &mut rng);
            let evaluator = Evaluator::new(params);
            let rots = rotation_indices(&evaluator);
            let levels = vec![0; rots.len()];
            let ek = EvaluationKey::new(evaluator.params(), &sk, &[0], &levels, &rots, &mut rng);
            Fixture { evaluator, sk, ek, rng }
        }
        fn enc(&mut self, m: &[u64]) -> Ciphertext {
            let pt = self.evaluator.plaintext_encode(m, Encoding::default());
            self.evaluator.encrypt(&self.sk, &pt, &mut self.rng)
        }
        fn dec(&self, ct: &Ciphertext) -> Vec<u64> {
            self.evaluator.plaintext_decode(&self.evaluator.decrypt(&self.sk, ct), Encoding::default())
        }
    }

    #[test]
    fn rotation_indices_are_right_shifts_below_the_lane() {
        let f = Fixture::new();
        assert_eq!(lane_len(&f.evaluator), 8);
        assert_eq!(rotation_indices(&f.evaluator), vec![-1, -2, -4]);
    }

    #[test]
    fn mask_keeps_only_flagged_slots() {
        let mut f = Fixture::new();
        let m: Vec<u64> = (1..=16).collect();
        let ct = f.enc(&m);
        let keep = [true, false, true, false, false, false, false, true];
        let out = f.dec(&mask(&f.evaluator, &ct, &keep));
        assert_eq!(out, vec![1, 0, 3, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn prefix_sum_matches_plaintext_in_both_rows() {
        let mut f = Fixture::new();
        let m: Vec<u64> = vec![5, 3, 0, 7, 1, 1, 2, 4, 10, 20, 30, 40, 50, 60, 70, 80];
        let ct = f.enc(&m);
        let out = f.dec(&prefix_sum(&f.evaluator, &ct, &f.ek));
        let mut want = vec![0u64; 16];
        for row in 0..2 {
            let mut run = 0;
            for i in 0..8 {
                run += m[row * 8 + i];
                want[row * 8 + i] = run;
            }
        }
        assert_eq!(out, want);
    }

    #[test]
    fn broadcast_sum_fills_each_row_with_its_total() {
        let mut f = Fixture::new();
        let m: Vec<u64> = vec![5, 3, 0, 7, 1, 1, 2, 4, 1, 1, 1, 1, 1, 1, 1, 1];
        let ct = f.enc(&m);
        let out = f.dec(&broadcast_sum(&f.evaluator, &ct, &f.ek));
        assert_eq!(out, [vec![23u64; 8], vec![8u64; 8]].concat());
    }

    /// The whole packed step for one lane: prefix sums of one side, the other side's total
    /// broadcast, one comparison, and the bits come out right. Also pins the noise, since
    /// the rotations and masks spend budget before the comparison does.
    #[test]
    fn one_comparison_gives_every_fill_bit_and_fits_the_budget() {
        let mut f = Fixture::new();
        // buys 1250 3400 800 2900 1900 4200 640 2750, sells summing to 9100
        let buys = vec![1250, 3400, 800, 2900, 1900, 4200, 640, 2750, 0, 0, 0, 0, 0, 0, 0, 0];
        let sells = vec![2000, 1100, 450, 3200, 700, 1650, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let buys_ct = f.enc(&buys);
        let sells_ct = f.enc(&sells);

        let prefix = prefix_sum(&f.evaluator, &buys_ct, &f.ek);
        let sell_total = broadcast_sum(&f.evaluator, &sells_ct, &f.ek);
        // over[i] = 1 where the cumulative buy volume through i exceeds the sell total
        let over = univariate_less_than(&f.evaluator, &sell_total, &prefix, &f.ek);

        let bits = f.dec(&over);
        // prefixes: 1250 4650 5450 8350 10250 14450 15090 17840 against 9100
        assert_eq!(&bits[..8], &[0, 0, 0, 0, 1, 1, 1, 1]);
        let noise = f.evaluator.measure_noise(&f.sk, &over);
        println!("noise after prefix + broadcast + comparison: {noise} bits of ~600");
        assert!(noise < 540, "only {} bits of budget left", 600 - noise as i64);
    }
}
