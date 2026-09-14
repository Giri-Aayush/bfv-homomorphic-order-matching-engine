use std::sync::OnceLock;

use bfv::{
    Ciphertext, Encoding, EvaluationKey, Evaluator, Modulus, PolyCache, PolyType, Representation,
};
use byteorder::{ByteOrder, LittleEndian};
use rayon::prelude::*;
use utils::store_values;

pub mod packed;
pub mod ranged;
pub mod roles;
pub mod utils;

/// Coefficients of g for t = 65537, produced once by `compute_lt_coefficients` and embedded
/// at build time so the binary and the tests need no data directory at run time.
const LT_COEFFICIENTS_LE: &[u8] = include_bytes!("../../../order-match-engine/data/less_than.bin");

/// Block size of the full circuit's baby-step giant-step split: 181² ≥ (t−1)/2.
const LT_BABY: usize = 181;

/// The g coefficients, padded to whole blocks of `LT_BABY` for `eval_bsgs`.
fn lt_coefficients() -> &'static [u64] {
    static DECODED: OnceLock<Vec<u64>> = OnceLock::new();
    DECODED.get_or_init(|| {
        let mut out = vec![0u64; LT_COEFFICIENTS_LE.len() / 8];
        LittleEndian::read_u64_into(LT_COEFFICIENTS_LE, &mut out);
        out.resize(out.len().div_ceil(LT_BABY) * LT_BABY, 0);
        out
    })
}

/// x^1 .. x^max, each relinearized. Built by doubling: once x^1..x^k are known, the next
/// k powers are x^k times each of them, and those multiplications are independent, so each
/// level runs on rayon. Depth is log2(max), the same as a squaring chain.
pub fn powers_of_x(
    evaluator: &Evaluator,
    x: &Ciphertext,
    max: usize,
    ek: &EvaluationKey,
) -> Vec<Ciphertext> {
    let mut values = vec![x.clone()];
    while values.len() < max {
        let k = values.len();
        let take = k.min(max - k);
        let top = &values[k - 1];
        let next: Vec<Ciphertext> = values[..take]
            .par_iter()
            .map(|p| evaluator.relinearize(&evaluator.mul(top, p), ek))
            .collect();
        values.extend(next);
    }
    values
}

pub fn sort(
    evaluator: &Evaluator,
    values: &[Ciphertext],
    ek: &EvaluationKey,
) -> Vec<Ciphertext> {
    let mut ht = vec![Ciphertext::placeholder(); values.len()];

    let one = evaluator.plaintext_encode(
        &vec![1; evaluator.params().degree],
        Encoding::simd(0, PolyCache::AddSub(Representation::Coefficient)),
    );

    println!("Sorting ciphertext ~~~~~~~~~");

    for i in 0..values.len() {
        for j in 0..values.len() {
            if i < j {
                let lt = univariate_less_than(evaluator, &values[i], &values[j], ek);

                let mut one_minus_lt = evaluator.negate(&lt);
                evaluator.add_assign_plaintext(&mut one_minus_lt, &one);

                // add lt to ht[i]
                if ht[i].c_ref().len() != 0 {
                    evaluator.add_assign(&mut ht[i], &lt);
                } else {
                    ht[i] = lt;
                }

                // add 1 - lt to ht[j]
                if ht[j].c_ref().len() != 0 {
                    evaluator.add_assign(&mut ht[j], &one_minus_lt);
                } else {
                    ht[j] = one_minus_lt;
                }
            }
        }
    }

    // equality checks

    // precompute powers
    let mut ht_powers = vec![];
    ht.iter().for_each(|c| {
        // change ciphertexts to Evaluation representation for plaintext multiplication
        let mut powers = powers_of_x(evaluator, c, 65536, ek);
        powers.iter_mut().for_each(|c| {
            evaluator.ciphertext_change_representation(c, Representation::Evaluation);
        });
        ht_powers.push(powers);
    });

    println!("Equality checks ~~~~~~~~~");

    let mut sorted_values = vec![];

    for i in 0..values.len() {
        // get `i_th` ciphertext in descending order
        sorted_values.push(sort_equality_subroutine(
            evaluator, i, &ht_powers, values, ek,
        ));
    }

    println!("Sorting ciphertext done!! ~~~~~~~~~");

    sorted_values
}

/// Returns ciphertext with hamming weight = `i`
pub fn sort_equality_subroutine(
    evaluator: &Evaluator,
    i: usize,
    ht_powers: &[Vec<Ciphertext>],
    values: &[Ciphertext],
    ek: &EvaluationKey,
) -> Ciphertext {
    let p = 65537;
    let modp = &evaluator.params().plaintext_modulus_op;

    let one_pt = evaluator.plaintext_encode(
        &vec![1; evaluator.params().degree],
        Encoding::simd(0, PolyCache::AddSub(Representation::Evaluation)),
    );

    let n = values.len();
    let mut i_pow_k = 1;
    let mut sum = vec![Ciphertext::placeholder(); values.len()];
    for k in 0..p {
        // i^0 = 1, so we don't need plaintext multiplication
        if k == 0 {
            for j in 0..n {
                sum[j] = ht_powers[j][p - 1 - (k + 1)].clone();
            }
        } else if k == p - 1 {
            // x^((p-1)-(p-1)) = x^0 = 1; We can ignore the ciphertext
            // and add 1 depending on value of `i`.
            // Since `i^(p-1) = 1` if i!=0, and 0 otherwise, we add 1
            // to sum when i != 0.
            if i != 0 {
                for j in 0..n {
                    evaluator.add_assign_plaintext(&mut sum[j], &one_pt);
                }
            }
        } else {
            // if i == 0, then i^k == 0 for k > 0 always. Thus plaintext multiplication
            // will always result in 0 ciphertext. So skip this part when i==0.
            if i != 0 {
                let pt = evaluator.plaintext_encode(
                    &vec![i_pow_k; evaluator.params().degree],
                    Encoding::simd(0, PolyCache::Mul(PolyType::Q)),
                );
                for j in 0..n {
                    evaluator.add_assign(
                        &mut sum[j],
                        &evaluator.mul_plaintext(&ht_powers[j][p - 1 - (k + 1)], &pt),
                    );
                }
            }
        }

        i_pow_k = modp.mul_mod_fast(i_pow_k, i as u64);
    }

    // 1 - sum[j]
    for j in 0..n {
        evaluator.negate_assign(&mut sum[j]);
        evaluator.add_assign_plaintext(&mut sum[j], &one_pt);
    }

    // sum[j] indicates whether hw of `j^th` ciphertext equals `i`. It's
    // 1 if it does, otherwise 0. We multiply `j^th` ciphertext by `sum[j]` (which is 0 or 1).
    // Each product copies over values from `j^th` ct only if ct's hw is `i`.
    // Summation of all products should only contain values of ciphertexts corresponding to hw = `i`
    // \sum_{j=0}^{N-1} sum[j] * values[j]
    let mut sum_all = Ciphertext::placeholder();
    for j in 0..n {
        // Since `sum[j]` is in Evaluation form and `values[j]` is in Coefficient, pass
        // `sum[j]` as the first operand.
        let product = evaluator.mul_lazy(&sum[j], &values[j]);

        if j == 0 {
            sum_all = product;
        } else {
            evaluator.add_assign(&mut sum_all, &product);
        }
    }

    let res = evaluator.scale_and_round(&mut sum_all);
    evaluator.relinearize(&res, ek)
}

/// Homomorphic x < y over Z_t with t = 65537, after Iliashenko and Zucca (PoPETs 2021).
/// Returns a ciphertext holding 1 in every slot where x < y and 0 elsewhere, correct for
/// inputs below t/2. Needs only the evaluation key: nothing here can decrypt.
pub fn univariate_less_than(
    evaluator: &Evaluator,
    x: &Ciphertext,
    y: &Ciphertext,
    ek: &EvaluationKey,
) -> Ciphertext {
    let z = evaluator.sub(x, y);
    let z_sq = evaluator.relinearize(&evaluator.mul(&z, &z), ek);

    // z^2..(z^2)^181, then (z^2)^181..((z^2)^181)^181
    let mut baby = powers_of_x(evaluator, &z_sq, LT_BABY, ek);
    let giant = powers_of_x(evaluator, &baby[LT_BABY - 1], LT_BABY, ek);

    // ((z^2)^181)^181 * (z^2)^7 = z^65536 = z^{t-1}, weighted by (t+1)/2
    let mut z_max_lazy = evaluator.mul_lazy(&giant[LT_BABY - 1], &baby[6]);
    let half = evaluator.plaintext_encode(
        &vec![32769; evaluator.params().degree],
        Encoding::simd(0, PolyCache::Mul(PolyType::PQ)),
    );
    evaluator.mul_poly_assign(&mut z_max_lazy, half.mul_poly_ref());

    // g(z^2), with the baby powers in evaluation form for the plaintext multiplies
    for p in baby.iter_mut() {
        evaluator.ciphertext_change_representation(p, Representation::Evaluation);
    }
    let g = ranged::eval_bsgs(evaluator, &baby, &giant, lt_coefficients(), ek);

    // ((t+1)/2) z^{t-1} + z * g(z^2)
    let z_gx = evaluator.mul_lazy(&g, &z);
    evaluator.add_assign(&mut z_max_lazy, &z_gx);
    let res = evaluator.scale_and_round(&mut z_max_lazy);
    evaluator.relinearize(&res, ek)
}

/// \alpha_i = \sum_{a = 1}^{\frac{p-1}{2}} a^{p - 1 - i}
pub fn compute_lt_coefficients(t: u64) -> Vec<u64> {
    let modt = Modulus::new(t);

    println!("Computing alpha vector!! ~~~~~~~~~");
    println!("t = {}", t);

    let mut alpha_vec = vec![];

    for i in 0..(t - 3 + 1) {
        // only when even
        if i & 1 == 0 {
            let mut alpha = 0;

            for a in 1..((t - 1) / 2) + 1 {
                alpha = modt.add_mod_fast(alpha, modt.exp(a, (t - 1 - (i + 1)) as usize));
            }
            alpha_vec.push(alpha);
        }
        println!("Reached i = {}", i);
    }
    println!("Alpha vector!! ~~~~~~~~~");
    println!("alpha_vec.len() = {}", alpha_vec.len());

    store_values(&alpha_vec, "less_than.bin");

    alpha_vec
}

#[cfg(test)]
mod tests {
    use super::*;
    use bfv::{BfvParameters, SecretKey};
    use rand::thread_rng;

    #[test]
    fn less_than_works() {
        let mut rng = thread_rng();

        let mut params = BfvParameters::new(&[60; 10], 65537, 1 << 4);
        params.enable_hybrid_key_switching(&[60; 3]);

        let modt_by_2 = Modulus::new(params.plaintext_modulus / 2);

        let sk = SecretKey::random_with_params(&params, &mut rng);
        let mx = modt_by_2.random_vec(params.degree, &mut rng);
        let my = modt_by_2.random_vec(params.degree, &mut rng);

        let ek = EvaluationKey::new(&params, &sk, &[0], &[], &[], &mut rng);

        let evaluator = Evaluator::new(params);

        let ptx = evaluator.plaintext_encode(&mx, Encoding::default());
        let pty = evaluator.plaintext_encode(&my, Encoding::default());
        let x = evaluator.encrypt(&sk, &ptx, &mut rng);
        let y = evaluator.encrypt(&sk, &pty, &mut rng);
        let res_ct = univariate_less_than(&evaluator, &x, &y, &ek);

        let res_m =
            evaluator.plaintext_decode(&evaluator.decrypt(&sk, &res_ct), Encoding::default());
        let expected = mx
            .iter()
            .zip(my.iter())
            .map(|(x, y)| if x < y { 1 } else { 0 })
            .collect::<Vec<u64>>();
        assert_eq!(res_m, expected);
    }

    /// One comparison, sixteen slots, each slot an edge of the input domain: equal operands,
    /// zero against one, the largest legal value against zero and against itself, and
    /// neighbours one apart in both directions. Also pins the noise left after the circuit,
    /// so a parameter change that silently eats the budget fails here instead of in a run.
    #[test]
    fn less_than_edges_and_noise_budget() {
        let mut rng = thread_rng();

        let mut params = BfvParameters::new(&[60; 10], 65537, 1 << 4);
        params.enable_hybrid_key_switching(&[60; 3]);
        let max = params.plaintext_modulus / 2 - 1; // 32767, the largest legal operand

        let sk = SecretKey::random_with_params(&params, &mut rng);
        let ek = EvaluationKey::new(&params, &sk, &[0], &[], &[], &mut rng);
        let evaluator = Evaluator::new(params);

        let mx = vec![0, 0, 1, max, max, 0, 7, 8, 100, 99, 5, max - 1, max, 1, 32000, 3];
        let my = vec![0, 1, 0, max, 0, max, 8, 7, 99, 100, 5, max, max - 1, 1, 32001, 3];
        let expected: Vec<u64> = mx.iter().zip(&my).map(|(x, y)| (x < y) as u64).collect();

        let x = evaluator.encrypt(&sk, &evaluator.plaintext_encode(&mx, Encoding::default()), &mut rng);
        let y = evaluator.encrypt(&sk, &evaluator.plaintext_encode(&my, Encoding::default()), &mut rng);
        let res = univariate_less_than(&evaluator, &x, &y, &ek);

        let bits = evaluator.plaintext_decode(&evaluator.decrypt(&sk, &res), Encoding::default());
        assert_eq!(bits, expected);

        // Q is ten 60-bit primes, about 600 bits. The circuit must leave real headroom.
        let noise_bits = evaluator.measure_noise(&sk, &res);
        println!("noise after comparison: {noise_bits} bits of ~600");
        assert!(noise_bits < 540, "comparison left only {} bits of budget", 600 - noise_bits as i64);
    }

    // #[test]
    // fn sort_univariate_works() {
    //     let mut rng = thread_rng();

    //     let mut params = BfvParameters::new(&[60; 15], 65537, 1 << 3);
    //     params.enable_hybrid_key_switching(&[60; 3]);

    //     let sk = SecretKey::random_with_params(&params, &mut rng);

    //     let ek = EvaluationKey::new(&params, &sk, &[0], &[], &[], &mut rng);

    //     let evaluator = Evaluator::new(params);
    //     let max = 5;
    //     let modt_by_2 = Modulus::new(evaluator.params().plaintext_modulus / 2);
    //     let m_values = (0..max)
    //         .into_iter()
    //         .map(|_| modt_by_2.random_vec(evaluator.params().degree, &mut rng))
    //         .collect::<Vec<Vec<u64>>>();
    //     let values = m_values
    //         .iter()
    //         .map(|i| {
    //             let pt = evaluator.plaintext_encode(i, Encoding::default());
    //             evaluator.encrypt(&sk, &pt, &mut rng)
    //         })
    //         .collect::<Vec<Ciphertext>>();

    //     let sorted_values = sort(&evaluator, &values, &ek, &sk);
    //     dbg!(evaluator.measure_noise(&sk, &sorted_values[0]));

    //     let m_sorted = sorted_values
    //         .iter()
    //         .map(|c| evaluator.plaintext_decode(&evaluator.decrypt(&sk, &c), Encoding::default()))
    //         .collect::<Vec<Vec<u64>>>();

    //     // check
    //     let row_size = evaluator.params().degree;

    //     for row_index in 0..row_size {
    //         let mut row_values = vec![];
    //         let mut row_sorted = vec![];
    //         for col_index in 0..max {
    //             row_values.push(m_values[col_index][row_index]);
    //             row_sorted.push(m_sorted[col_index][row_index]);
    //         }

    //         row_values.sort_by(|a, b| b.cmp(a));

    //         assert_eq!(row_values, row_sorted);
    //     }
    // }
}

