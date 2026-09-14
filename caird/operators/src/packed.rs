//! Several values per ciphertext, one per SIMD slot, and the row-wise primitives a packed
//! matcher needs: prefix sums, row totals broadcast to every slot, and 0/1 masks.
//!
//! BFV batching lays the n slots out as two rows of n/2. This library's Galois keys rotate
//! within a row and it has no row swap, so a lane lives in one row. It uses only the first
//! half of that row, `lane_len` = n/4 slots, so that a right rotation by less than a lane
//! wraps zeros in from the empty half. That is what lets `prefix_sum` run without a mask:
//! rotations add a little additive noise, a step mask multiplies noise by about t·√n, and
//! at n = 2^15 fourteen of those ate the whole budget. The second row is carried unused.

use bfv::{Ciphertext, Encoding, EvaluationKey, Evaluator, PolyCache, PolyType, Representation};

/// Slots per row of the slot matrix, which is as far as a rotation reaches.
fn row_len(evaluator: &Evaluator) -> usize {
    evaluator.params().degree / 2
}

/// Values a caller may pack per ciphertext: the first half of a row, from slot 0.
pub fn lane_len(evaluator: &Evaluator) -> usize {
    row_len(evaluator) / 2
}

/// The rotation indices `prefix_sum` and `broadcast_sum` need keys for: right shifts by
/// 1, 2, 4, ... below the row length. Pass these as `rtg_indices` to `EvaluationKey::new`.
pub fn rotation_indices(evaluator: &Evaluator) -> Vec<isize> {
    let row = row_len(evaluator);
    (0..)
        .map(|k| 1usize << k)
        .take_while(|&s| s < row)
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

/// Prefix sums over a lane: slot i becomes the sum of slots 0..=i, for i below the lane
/// length. Slots at or past the lane are unspecified.
///
/// Doubling with right rotations by 1, 2, 4, ... below the lane length, and no masks. With
/// the top half of the row zero, every wrap brings in zeros, and the window each slot sums
/// covers the whole lane by the last step. Additive noise only, so it works at any degree.
pub fn prefix_sum(evaluator: &Evaluator, ct: &Ciphertext, ek: &EvaluationKey) -> Ciphertext {
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

/// Every slot of a row becomes that row's sum. log2(row) rotate-and-adds, no masks.
pub fn broadcast_sum(evaluator: &Evaluator, ct: &Ciphertext, ek: &EvaluationKey) -> Ciphertext {
    let row = row_len(evaluator);
    let mut acc = ct.clone();
    let mut shift = 1;
    while shift < row {
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
    fn a_lane_is_half_a_row_and_keys_cover_the_row() {
        let f = Fixture::new();
        assert_eq!(lane_len(&f.evaluator), 4);
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
    fn prefix_sum_matches_plaintext_within_the_lane() {
        let mut f = Fixture::new();
        // one lane of four in row 0, another in row 1, top halves zero
        let m: Vec<u64> = vec![5, 3, 0, 7, 0, 0, 0, 0, 10, 20, 30, 40, 0, 0, 0, 0];
        let ct = f.enc(&m);
        let out = f.dec(&prefix_sum(&f.evaluator, &ct, &f.ek));
        assert_eq!(&out[..4], &[5, 8, 8, 15]);
        assert_eq!(&out[8..12], &[10, 30, 60, 100]);
        let noise = f.evaluator.measure_noise(&f.sk, &prefix_sum(&f.evaluator, &ct, &f.ek));
        let fresh = f.evaluator.measure_noise(&f.sk, &ct);
        assert!(noise < fresh + 40, "prefix sum should add only key-switching noise, added {}", noise - fresh);
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
        // one lane of buys, sells summing to 5450 in another ciphertext's lane
        let buys = vec![1250, 3400, 800, 2900, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let sells = vec![2000, 1100, 450, 1900, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let buys_ct = f.enc(&buys);
        let sells_ct = f.enc(&sells);

        let prefix = prefix_sum(&f.evaluator, &buys_ct, &f.ek);
        let sell_total = broadcast_sum(&f.evaluator, &sells_ct, &f.ek);
        // over[i] = 1 where the cumulative buy volume through i exceeds the sell total
        let over = univariate_less_than(&f.evaluator, &sell_total, &prefix, &f.ek);

        let bits = f.dec(&over);
        // prefixes: 1250 4650 5450 8350 against 5450: 5450 is not over
        assert_eq!(&bits[..4], &[0, 0, 0, 1]);
        let noise = f.evaluator.measure_noise(&f.sk, &over);
        println!("noise after prefix + broadcast + comparison: {noise} bits of ~600");
        assert!(noise < 540, "only {} bits of budget left", 600 - noise as i64);
    }
}
