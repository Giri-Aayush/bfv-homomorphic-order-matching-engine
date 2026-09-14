//! Less-than for operands below a known bound, evaluated as two polynomials in z² of degree
//! about R instead of the full-domain circuit's 32768.
//!
//! With z = x − y and both operands below R, the sign only has to be right on the 2R−1
//! values z can take, so
//!
//!   LT(x, y) = (1 − e(z²) − z·h(z²)) / 2
//!
//! where e(w) is 1 at w = 0 and 0 at w = k² for 0 < k < R, and h(k²) = 1/k. That is the same
//! odd/even split the full-domain circuit uses, on a smaller domain, with the two tables
//! interpolated once per R rather than derived from Fermat. Cost tracks R, not t: the ladders
//! are about 2√R ciphertext multiplications and the accumulation R plaintext ones.
//!
//! Measured at n = 16 against the full circuit's 0.061 s: R = 1024 evaluates in 0.006 s,
//! 4096 in 0.017 s, 8192 in 0.032 s. The bit form evaluates both e and h, so it costs 2R
//! plaintext multiplies and only beats the full circuit below R ≈ t/4. `compare_ranged`
//! skips e and returns a three-valued result for callers that decrypt anyway: R plaintext
//! multiplies, and it never loses. This is the trade a venue can actually make: coarser
//! lots, cheaper comparisons.

use std::sync::OnceLock;

use bfv::{
    Ciphertext, Encoding, EvaluationKey, Evaluator, Modulus, PolyCache, PolyType, Representation,
};
use byteorder::{ByteOrder, LittleEndian};

use crate::powers_of_x;

/// h tables shipped for the ranges a book is likely to need, built once by the operators
/// binary (`operators ranged <R>`). Only h: these back `compare_ranged`, and the full-circuit
/// table already covers callers that need a bit inside the encrypted domain.
const SHIPPED: &[(u64, &[u8])] = &[
    (4096, include_bytes!("../../../order-match-engine/data/lt-h-4096.bin")),
    (16384, include_bytes!("../../../order-match-engine/data/lt-h-16384.bin")),
];

/// Interpolated tables for one bound. Both are already halved, so the evaluators compute
/// inv2 − e'(w) − z·h'(w) or inv2 − z·h'(w) with no scalar multiply at the end. Coefficients
/// are ascending in w and padded to a whole number of baby blocks.
pub struct LtTable {
    pub range: u64,
    pub baby: usize,
    e: Vec<u64>,
    h: Vec<u64>,
    inv2: u64,
}

impl LtTable {
    /// Build the tables for operands in [0, range). O(range²) modular multiplications, done once.
    pub fn for_range(t: u64, range: u64) -> Self {
        assert!(range >= 2 && range <= t / 2, "range must be in [2, t/2]");
        let modt = Modulus::new(t);
        let m = (range - 1) as usize; // points k = 1..=m
        let inv2 = modt.inv(2);

        // Master polynomial M(w) = Π (w − k²), ascending coefficients.
        let mut master = vec![1u64];
        for k in 1..=m as u64 {
            let wk = modt.mul_mod_fast(k, k);
            let neg_wk = modt.neg_mod_fast(wk);
            let mut next = vec![0u64; master.len() + 1];
            for (i, &c) in master.iter().enumerate() {
                next[i] = modt.add_mod_fast(next[i], modt.mul_mod_fast(c, neg_wk));
                next[i + 1] = modt.add_mod_fast(next[i + 1], c);
            }
            master = next;
        }

        // e(w) = M(w) / M(0): 1 at zero, 0 at every k².
        let scale_e = modt.mul_mod_fast(modt.inv(master[0]), inv2);
        let e: Vec<u64> = master.iter().map(|&c| modt.mul_mod_fast(c, scale_e)).collect();

        // h by Lagrange on (k², 1/k): each basis term is M(w)/(w − k²) scaled by the value
        // over the derivative, and synthetic division gives the quotient in O(m).
        let mut h = vec![0u64; m.max(1)];
        let mut quotient = vec![0u64; m];
        for k in 1..=m as u64 {
            let wk = modt.mul_mod_fast(k, k);
            // quotient of M by (w − wk): Horner from the top coefficient down
            let mut carry = master[m];
            for i in (0..m).rev() {
                quotient[i] = carry;
                carry = modt.add_mod_fast(master[i], modt.mul_mod_fast(carry, wk));
            }
            // quotient(wk) is M'(wk)
            let mut deriv = 0u64;
            for &c in quotient.iter().rev() {
                deriv = modt.add_mod_fast(modt.mul_mod_fast(deriv, wk), c);
            }
            let weight = modt.mul_mod_fast(modt.mul_mod_fast(modt.inv(k), modt.inv(deriv)), inv2);
            for i in 0..m {
                h[i] = modt.add_mod_fast(h[i], modt.mul_mod_fast(quotient[i], weight));
            }
        }

        let mut table = LtTable { range, baby: Self::baby_for(range), e, h, inv2 };
        table.pad();
        table
    }

    /// The smallest shipped table whose range covers `range`, if any. Loaded once.
    pub fn shipped(range: u64) -> Option<&'static LtTable> {
        static TABLES: OnceLock<Vec<LtTable>> = OnceLock::new();
        let tables = TABLES.get_or_init(|| {
            SHIPPED.iter().map(|&(r, bytes)| Self::from_h_bytes(65537, r, bytes)).collect()
        });
        tables.iter().find(|t| t.range >= range)
    }

    /// Raw h coefficients as written by `store_h`. Such a table has no equality polynomial,
    /// so it serves `compare_ranged` only.
    fn from_h_bytes(t: u64, range: u64, bytes: &[u8]) -> Self {
        let mut h = vec![0u64; bytes.len() / 8];
        LittleEndian::read_u64_into(bytes, &mut h);
        assert_eq!(h.len() as u64, range - 1, "h table for range {range} has the wrong length");
        let mut table = LtTable { range, baby: Self::baby_for(range), e: vec![], h, inv2: Modulus::new(t).inv(2) };
        table.pad();
        table
    }

    /// Write the unpadded h coefficients to `data/lt-h-<range>.bin` for shipping.
    pub fn store_h(&self) {
        let m = self.range as usize - 1;
        crate::utils::store_values(&self.h[..m], &format!("lt-h-{}.bin", self.range));
    }

    fn baby_for(range: u64) -> usize {
        ((range as f64).sqrt().ceil() as usize).max(2)
    }

    /// Pad both tables to a whole number of baby blocks so every block has a w^1 term.
    fn pad(&mut self) {
        let b = self.baby;
        for v in [&mut self.e, &mut self.h] {
            let blocks = v.len().div_ceil(b);
            v.resize(blocks * b, 0);
        }
    }

    pub fn degree(&self) -> usize {
        self.range as usize - 1
    }

    fn giant_steps(&self) -> usize {
        self.e.len().max(self.h.len()) / self.baby - 1
    }

    /// Value `compare_ranged` returns in a slot where the operands are equal.
    pub fn equal_marker(&self) -> u64 {
        self.inv2
    }
}

/// Σ c_j w^j by baby-step giant-step. `baby` holds w^1..w^b in evaluation form for the
/// plaintext multiplies, `giant` holds (w^b)^1.. in coefficient form for the lazy products.
fn eval_bsgs(
    evaluator: &Evaluator,
    baby: &[Ciphertext],
    giant: &[Ciphertext],
    coeffs: &[u64],
    ek: &EvaluationKey,
) -> Ciphertext {
    let b = baby.len();
    let n = evaluator.params().degree;
    let blocks = coeffs.len() / b;
    let mut left_over = Ciphertext::placeholder();
    let mut sum_k = Ciphertext::placeholder();

    for k in 0..blocks {
        let block = &coeffs[k * b..(k + 1) * b];
        let x0 = evaluator.plaintext_encode(
            &vec![block[0]; n],
            Encoding::simd(0, PolyCache::AddSub(Representation::Evaluation)),
        );
        let mut sum_m = Ciphertext::placeholder();
        for (m, &c) in block.iter().enumerate().skip(1) {
            let pt = evaluator.plaintext_encode(&vec![c; n], Encoding::simd(0, PolyCache::Mul(PolyType::Q)));
            let term = evaluator.mul_poly(&baby[m - 1], pt.mul_poly_ref());
            if m == 1 {
                sum_m = term;
            } else {
                evaluator.add_assign(&mut sum_m, &term);
            }
        }
        evaluator.add_assign_plaintext(&mut sum_m, &x0);

        if k == 0 {
            evaluator.ciphertext_change_representation(&mut sum_m, Representation::Coefficient);
            left_over = sum_m;
        } else {
            // sum_m is in evaluation form, giant in coefficient form: sum_m goes first.
            let product = evaluator.mul_lazy(&sum_m, &giant[k - 1]);
            if k == 1 {
                sum_k = product;
            } else {
                evaluator.add_assign(&mut sum_k, &product);
            }
        }
    }

    if blocks == 1 {
        return left_over;
    }
    let mut out = evaluator.relinearize(&evaluator.scale_and_round(&mut sum_k), ek);
    evaluator.add_assign(&mut out, &left_over);
    out
}

/// The shared front half: both power ladders of z², and z·h'(z²).
fn ladders_and_zh(
    evaluator: &Evaluator,
    x: &Ciphertext,
    y: &Ciphertext,
    ek: &EvaluationKey,
    table: &LtTable,
) -> (Vec<Ciphertext>, Vec<Ciphertext>, Ciphertext) {
    let z = evaluator.sub(x, y);
    let w = evaluator.relinearize(&evaluator.mul(&z, &z), ek);

    let mut baby = powers_of_x(evaluator, &w, table.baby, ek);
    let giant = match table.giant_steps() {
        0 => vec![],
        g => powers_of_x(evaluator, &baby[table.baby - 1], g, ek),
    };
    for p in baby.iter_mut() {
        evaluator.ciphertext_change_representation(p, Representation::Evaluation);
    }

    let h = eval_bsgs(evaluator, &baby, &giant, &table.h, ek);
    let zh = evaluator.relinearize(&evaluator.scale_and_round(&mut evaluator.mul_lazy(&h, &z)), ek);
    (baby, giant, zh)
}

/// inv2 − rest, in place.
fn half_minus(evaluator: &Evaluator, table: &LtTable, mut rest: Ciphertext) -> Ciphertext {
    evaluator.negate_assign(&mut rest);
    let half = evaluator.plaintext_encode(
        &vec![table.inv2; evaluator.params().degree],
        Encoding::simd(0, PolyCache::AddSub(Representation::Coefficient)),
    );
    evaluator.add_assign_plaintext(&mut rest, &half);
    rest
}

/// x < y for x, y below `table.range`. Returns 1 in each slot where it holds, else 0.
/// Same depth as `univariate_less_than`: one squaring, two ladders, one lazy block product,
/// one final multiply by z. Costs 2R plaintext multiplies, so it only beats the full circuit
/// below R ≈ t/4; use `compare_ranged` when the result is going to be decrypted.
pub fn less_than_ranged(
    evaluator: &Evaluator,
    x: &Ciphertext,
    y: &Ciphertext,
    ek: &EvaluationKey,
    table: &LtTable,
) -> Ciphertext {
    let (baby, giant, zh) = ladders_and_zh(evaluator, x, y, ek, table);
    assert!(!table.e.is_empty(), "this table was loaded from shipped h coefficients and has no equality polynomial; build one with LtTable::for_range");
    let e = eval_bsgs(evaluator, &baby, &giant, &table.e, ek);
    half_minus(evaluator, table, evaluator.add(&e, &zh))
}

/// Three-valued x ? y for x, y below `table.range`, for callers that decrypt the result:
/// 1 where x < y, 0 where x > y, and `table.equal_marker()` where they are equal. Skips the
/// equality polynomial, so R plaintext multiplies instead of 2R.
pub fn compare_ranged(
    evaluator: &Evaluator,
    x: &Ciphertext,
    y: &Ciphertext,
    ek: &EvaluationKey,
    table: &LtTable,
) -> Ciphertext {
    let (_, _, zh) = ladders_and_zh(evaluator, x, y, ek, table);
    half_minus(evaluator, table, zh)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::univariate_less_than;
    use bfv::{BfvParameters, SecretKey};
    use rand::{thread_rng, Rng};
    use std::time::Instant;

    const T: u64 = 65537;

    struct Fixture {
        evaluator: Evaluator,
        sk: SecretKey,
        ek: EvaluationKey,
        rng: rand::rngs::ThreadRng,
    }

    impl Fixture {
        fn new() -> Self {
            let mut rng = thread_rng();
            let mut params = BfvParameters::new(&[60; 10], T, 1 << 4);
            params.enable_hybrid_key_switching(&[60; 3]);
            let sk = SecretKey::random_with_params(&params, &mut rng);
            let ek = EvaluationKey::new(&params, &sk, &[0], &[], &[], &mut rng);
            Fixture { evaluator: Evaluator::new(params), sk, ek, rng }
        }
        fn enc(&mut self, m: &[u64]) -> Ciphertext {
            let pt = self.evaluator.plaintext_encode(m, Encoding::default());
            self.evaluator.encrypt(&self.sk, &pt, &mut self.rng)
        }
        fn dec(&self, ct: &Ciphertext) -> Vec<u64> {
            self.evaluator.plaintext_decode(&self.evaluator.decrypt(&self.sk, ct), Encoding::default())
        }
        fn noise(&self, ct: &Ciphertext) -> u64 {
            self.evaluator.measure_noise(&self.sk, ct)
        }
    }

    fn expected(x: &[u64], y: &[u64]) -> Vec<u64> {
        x.iter().zip(y).map(|(a, b)| (a < b) as u64).collect()
    }

    #[test]
    fn tables_hit_their_interpolation_points() {
        let t = LtTable::for_range(T, 40);
        let modt = Modulus::new(T);
        let eval = |coeffs: &[u64], w: u64| coeffs.iter().rev().fold(0u64, |acc, &c| modt.add_mod_fast(modt.mul_mod_fast(acc, w), c));
        let two = 2u64;
        // e'(0) = 1/2, e'(k²) = 0 ; h'(k²) = 1/(2k)
        assert_eq!(modt.mul_mod_fast(eval(&t.e, 0), two), 1);
        for k in 1..40u64 {
            let wk = modt.mul_mod_fast(k, k);
            assert_eq!(eval(&t.e, wk), 0, "e at k={k}");
            assert_eq!(modt.mul_mod_fast(modt.mul_mod_fast(eval(&t.h, wk), two), k), 1, "h at k={k}");
        }
    }

    #[test]
    fn exhaustive_on_a_small_range() {
        let mut f = Fixture::new();
        let range = 24u64;
        let table = LtTable::for_range(T, range);
        let pairs: Vec<(u64, u64)> = (0..range).flat_map(|x| (0..range).map(move |y| (x, y))).collect();
        for chunk in pairs.chunks(16) {
            let mut x = vec![0u64; 16];
            let mut y = vec![0u64; 16];
            for (i, &(a, b)) in chunk.iter().enumerate() {
                x[i] = a;
                y[i] = b;
            }
            let cx = f.enc(&x);
            let cy = f.enc(&y);
            let got = f.dec(&less_than_ranged(&f.evaluator, &cx, &cy, &f.ek, &table));
            assert_eq!(got, expected(&x, &y), "x={x:?} y={y:?}");

            let three = f.dec(&compare_ranged(&f.evaluator, &cx, &cy, &f.ek, &table));
            let want: Vec<u64> = x
                .iter()
                .zip(&y)
                .map(|(a, b)| if a < b { 1 } else if a > b { 0 } else { table.equal_marker() })
                .collect();
            assert_eq!(three, want, "compare x={x:?} y={y:?}");
        }
    }

    #[test]
    fn shipped_tables_cover_their_ranges_and_compare_correctly() {
        let mut f = Fixture::new();
        assert!(LtTable::shipped(20_000).is_none());
        let small = LtTable::shipped(3000).unwrap();
        let big = LtTable::shipped(13731).unwrap();
        assert_eq!((small.range, big.range), (4096, 16384));

        let x = vec![13730, 0, 4095, 1, 9999, 16383, 7, 7, 0, 0, 0, 0, 0, 0, 0, 0];
        let y = vec![13731, 0, 4094, 0, 9999, 0, 8, 6, 0, 0, 0, 0, 0, 0, 0, 0];
        let cx = f.enc(&x);
        let cy = f.enc(&y);
        let got = f.dec(&compare_ranged(&f.evaluator, &cx, &cy, &f.ek, big));
        let want: Vec<u64> = x
            .iter()
            .zip(&y)
            .map(|(a, b)| if a < b { 1 } else if a > b { 0 } else { big.equal_marker() })
            .collect();
        assert_eq!(got, want);
    }

    #[test]
    fn agrees_with_the_full_circuit_below_the_range_and_costs_less() {
        let mut f = Fixture::new();
        let range = 4096u64;
        let built = Instant::now();
        let table = LtTable::for_range(T, range);
        let build_secs = built.elapsed().as_secs_f64();

        let max = range - 1;
        let mut x = vec![0, 0, 1, max, max, 0, 7, 8, 100, 99, 5, max - 1, max, 1, 4000, 3];
        let mut y = vec![0, 1, 0, max, 0, max, 8, 7, 99, 100, 5, max, max - 1, 1, 4001, 3];
        for _ in 0..3 {
            let cx = f.enc(&x);
            let cy = f.enc(&y);

            let t0 = Instant::now();
            let ranged = less_than_ranged(&f.evaluator, &cx, &cy, &f.ek, &table);
            let ranged_secs = t0.elapsed().as_secs_f64();
            let t1 = Instant::now();
            let full = univariate_less_than(&f.evaluator, &cx, &cy, &f.ek);
            let full_secs = t1.elapsed().as_secs_f64();
            let t2 = Instant::now();
            let three = compare_ranged(&f.evaluator, &cx, &cy, &f.ek, &table);
            let three_secs = t2.elapsed().as_secs_f64();
            let three_want: Vec<u64> = x
                .iter()
                .zip(&y)
                .map(|(a, b)| if a < b { 1 } else if a > b { 0 } else { table.equal_marker() })
                .collect();
            assert_eq!(f.dec(&three), three_want);

            let want = expected(&x, &y);
            assert_eq!(f.dec(&ranged), want);
            assert_eq!(f.dec(&full), want);
            let noise = f.noise(&ranged);
            println!(
                "R={range} degree={} baby={} table {build_secs:.2}s | bit {ranged_secs:.3}s noise {noise} | three-valued {three_secs:.3}s noise {} | full {full_secs:.3}s noise {}",
                table.degree(), table.baby, f.noise(&three), f.noise(&full)
            );
            assert!(noise < 540, "only {} bits of budget left", 600 - noise as i64);

            for v in x.iter_mut().chain(y.iter_mut()) {
                *v = f.rng.gen_range(0..range);
            }
        }
    }
}

