//! Keys for three roles instead of one process: a public key so submitters can encrypt
//! without ever holding the secret, an evaluation key for the matcher, and a 2-of-3 split
//! of the secret so no single party can decrypt.
//!
//! The vendored library is symmetric-key only, so the public key is built here from the
//! same ring operations it exposes: with secret s, sample a uniform a and Gaussian e and
//! publish (p0, p1) = (−(a·s + e), a). Encrypting m samples a ternary u and two Gaussians
//! and sets (c0, c1) = (p0·u + e1 + Δm, p1·u + e2). Decrypting gives Δm + (e1 + e2·s − e·u),
//! a little more fresh noise than the symmetric form and otherwise the same ciphertext.
//!
//! The split is replicated 2-of-3: s = s0 + s1 + s2 with s0, s1 uniform, and party i holds
//! (s_i, s_{i+1}). Any two parties hold all three parts, one party holds two. Decryption is
//! linear in s, so each party contributes c1 times the parts assigned to it plus smudging
//! noise, and the combiner adds c0. Smudging hides the ciphertext's own noise from the
//! combiner, since that noise depends on the computation's inputs. The shares are uniform
//! in R_Q, so they hide the secret on their own.

use bfv::{BfvParameters, Ciphertext, Evaluator, Plaintext, Poly, PolyType, Representation, SecretKey};
use num_bigint::RandBigInt;
use rand::{CryptoRng, Rng, RngCore};

fn ctx(evaluator: &Evaluator) -> bfv::PolyContext<'_> {
    evaluator.params().poly_ctx(&PolyType::Q, 0)
}

/// The dealer's copy of the secret: ternary, Hamming weight n/2, the distribution the
/// library's own `SecretKey::random` uses. Meant to be split and then dropped.
pub struct Secret {
    coefficients: Vec<i64>,
}

impl Secret {
    pub fn generate<R: CryptoRng + RngCore>(params: &BfvParameters, rng: &mut R) -> Self {
        let n = params.degree;
        let mut coefficients = vec![0i64; n];
        let mut free: Vec<usize> = (0..n).collect();
        for _ in 0..params.hw {
            let pick = rng.gen_range(0..free.len());
            let index = free.swap_remove(pick);
            coefficients[index] = if rng.gen::<bool>() { 1 } else { -1 };
        }
        Secret { coefficients }
    }

    /// The secret as a library key, for tests and for a single-party engine.
    pub fn secret_key(&self) -> SecretKey {
        SecretKey::new(self.coefficients.clone(), self.coefficients.len())
    }

    pub fn public_key<R: CryptoRng + RngCore>(&self, evaluator: &Evaluator, rng: &mut R) -> PublicKey {
        let ctx = ctx(evaluator);
        let mut s = ctx.try_convert_from_i64_small(&self.coefficients, Representation::Coefficient);
        ctx.change_representation(&mut s, Representation::Evaluation);
        let a = ctx.random(Representation::Evaluation, rng);
        let mut e = ctx.random_gaussian(Representation::Coefficient, evaluator.params().variance, rng);
        ctx.change_representation(&mut e, Representation::Evaluation);
        // p0 = −(a·s + e)
        let mut p0 = ctx.mul(&a, &s);
        ctx.add_assign(&mut p0, &e);
        ctx.neg_assign(&mut p0);
        PublicKey { p0, p1: a }
    }

    /// Replicated 2-of-3 shares. The dealer should drop `self` after this.
    pub fn split<R: CryptoRng + RngCore>(&self, evaluator: &Evaluator, rng: &mut R) -> [Share; 3] {
        let ctx = ctx(evaluator);
        let mut s = ctx.try_convert_from_i64_small(&self.coefficients, Representation::Coefficient);
        ctx.change_representation(&mut s, Representation::Evaluation);
        let s0 = ctx.random(Representation::Evaluation, rng);
        let s1 = ctx.random(Representation::Evaluation, rng);
        let mut s2 = s;
        ctx.sub_assign(&mut s2, &s0);
        ctx.sub_assign(&mut s2, &s1);
        [
            Share { party: 0, parts: [s0.clone(), s1.clone()] },
            Share { party: 1, parts: [s1, s2.clone()] },
            Share { party: 2, parts: [s2, s0] },
        ]
    }
}

pub struct PublicKey {
    p0: Poly,
    p1: Poly,
}

impl PublicKey {
    /// (−(a·s + e), a) in evaluation form, from wherever it was produced.
    pub(crate) fn from_parts(p0: Poly, p1: Poly) -> PublicKey {
        PublicKey { p0, p1 }
    }

    /// Encrypt an encoded plaintext at level 0.
    pub fn encrypt<R: CryptoRng + RngCore>(&self, evaluator: &Evaluator, pt: &Plaintext, rng: &mut R) -> Ciphertext {
        let params = evaluator.params();
        let ctx = ctx(evaluator);
        let n = params.degree;

        let u_coeffs: Vec<i64> = (0..n).map(|_| rng.gen_range(-1i64..=1)).collect();
        let mut u = ctx.try_convert_from_i64_small(&u_coeffs, Representation::Coefficient);
        ctx.change_representation(&mut u, Representation::Evaluation);
        let mut e1 = ctx.random_gaussian(Representation::Coefficient, params.variance, rng);
        ctx.change_representation(&mut e1, Representation::Evaluation);
        let mut e2 = ctx.random_gaussian(Representation::Coefficient, params.variance, rng);
        ctx.change_representation(&mut e2, Representation::Evaluation);
        let m = pt.scale_plaintext(params, Representation::Evaluation);

        // c0 = p0·u + e1 + Δm, c1 = p1·u + e2
        let mut c0 = ctx.mul(&self.p0, &u);
        ctx.add_assign(&mut c0, &e1);
        ctx.add_assign(&mut c0, &m);
        let mut c1 = ctx.mul(&self.p1, &u);
        ctx.add_assign(&mut c1, &e2);
        ctx.change_representation(&mut c0, Representation::Coefficient);
        ctx.change_representation(&mut c1, Representation::Coefficient);
        Ciphertext::new(vec![c0, c1], PolyType::Q, 0)
    }
}

/// One party's share: the two of three additive parts it holds.
pub struct Share {
    party: usize,
    parts: [Poly; 2],
}

/// One party's contribution to decrypting one ciphertext, computed for a specific partner.
pub struct Partial {
    party: usize,
    partner: usize,
    poly: Poly,
}

impl Share {
    /// Parts `party` and `party + 1` of an additive three-way split, in evaluation form.
    pub(crate) fn from_parts(party: usize, parts: [Poly; 2]) -> Share {
        Share { party, parts }
    }

    pub fn party(&self) -> usize {
        self.party
    }

    /// Which of the three parts this party contributes when decrypting with `partner`: each
    /// part goes to the lower-numbered party that holds it, so the two contributions are
    /// disjoint and cover all three.
    fn parts_with(&self, partner: usize) -> Vec<&Poly> {
        assert!(partner != self.party && partner < 3, "partner must be one of the other two parties");
        let holds = |party: usize, part: usize| part == party || part == (party + 1) % 3;
        (0..3)
            .filter(|&part| holds(self.party, part) && (!holds(partner, part) || self.party < partner))
            .map(|part| if part == self.party { &self.parts[0] } else { &self.parts[1] })
            .collect()
    }

    /// c1 times this party's assigned parts, plus `smudge_bits` of uniform noise. Only for
    /// two-component ciphertexts, which every relinearized result is.
    pub fn partial_decrypt<R: CryptoRng + RngCore>(
        &self,
        evaluator: &Evaluator,
        ct: &Ciphertext,
        partner: usize,
        smudge_bits: u64,
        rng: &mut R,
    ) -> Partial {
        assert_eq!(ct.c_ref().len(), 2, "threshold decryption needs a relinearized ciphertext");
        let ctx = ctx(evaluator);
        let mut c1 = ct.c_ref()[1].clone();
        ctx.change_representation(&mut c1, Representation::Evaluation);

        let mut mine = ctx.zero(Representation::Evaluation);
        for part in self.parts_with(partner) {
            ctx.add_assign(&mut mine, part);
        }
        let mut poly = ctx.mul(&c1, &mine);

        let smudge: Vec<_> = (0..evaluator.params().degree).map(|_| rng.gen_biguint(smudge_bits)).collect();
        let mut smudge = ctx.try_convert_from_biguint(&smudge, Representation::Coefficient);
        ctx.change_representation(&mut smudge, Representation::Evaluation);
        ctx.add_assign(&mut poly, &smudge);
        Partial { party: self.party, partner, poly }
    }
}

/// Add c0 to the partials and decode. The sum is Δm plus noise, which is what a decryption
/// holds just before decoding. The library only exposes decoding through `decrypt`, so the
/// sum is fed to it as (sum, 0) under a null key, where the key term is zero.
pub fn combine(evaluator: &Evaluator, ct: &Ciphertext, partials: &[Partial]) -> Vec<u64> {
    assert_eq!(partials.len(), 2, "2-of-3: exactly two partials");
    let (a, b) = (&partials[0], &partials[1]);
    assert!(
        a.party != b.party && a.partner == b.party && b.partner == a.party,
        "partials must be a matched pair: each computed for the other party"
    );
    let ctx = ctx(evaluator);
    let mut sum = ct.c_ref()[0].clone();
    ctx.change_representation(&mut sum, Representation::Evaluation);
    for p in partials {
        ctx.add_assign(&mut sum, &p.poly);
    }
    ctx.change_representation(&mut sum, Representation::Coefficient);
    let zero = ctx.zero(Representation::Coefficient);
    let decodable = Ciphertext::new(vec![sum, zero], PolyType::Q, 0);
    let null_key = SecretKey::new(vec![0; evaluator.params().degree], evaluator.params().degree);
    evaluator.plaintext_decode(&evaluator.decrypt(&null_key, &decodable), bfv::Encoding::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ranged::{compare_ranged, LtTable};
    use crate::univariate_less_than;
    use bfv::{Encoding, EvaluationKey};
    use rand::thread_rng;

    const T: u64 = 65537;
    const SMUDGE: u64 = 520;

    fn setup() -> (Evaluator, Secret, PublicKey, EvaluationKey, [Share; 3]) {
        let mut rng = thread_rng();
        let mut params = BfvParameters::new(&[60; 10], T, 1 << 4);
        params.enable_hybrid_key_switching(&[60; 3]);
        let secret = Secret::generate(&params, &mut rng);
        let sk = secret.secret_key();
        let ek = EvaluationKey::new(&params, &sk, &[0], &[], &[], &mut rng);
        let evaluator = Evaluator::new(params);
        let pk = secret.public_key(&evaluator, &mut rng);
        let shares = secret.split(&evaluator, &mut rng);
        (evaluator, secret, pk, ek, shares)
    }

    #[test]
    fn public_key_ciphertexts_decrypt_under_the_secret() {
        let (ev, secret, pk, _, _) = setup();
        let mut rng = thread_rng();
        let m: Vec<u64> = (0..16).map(|i| i * 1000 + 7).collect();
        let ct = pk.encrypt(&ev, &ev.plaintext_encode(&m, Encoding::default()), &mut rng);
        let sk = secret.secret_key();
        assert_eq!(ev.plaintext_decode(&ev.decrypt(&sk, &ct), Encoding::default()), m);

        let sym = ev.encrypt(&sk, &ev.plaintext_encode(&m, Encoding::default()), &mut rng);
        let (pk_noise, sym_noise) = (ev.measure_noise(&sk, &ct), ev.measure_noise(&sk, &sym));
        println!("fresh noise: public key {pk_noise} bits, symmetric {sym_noise} bits");
        assert!(pk_noise < sym_noise + 24, "public-key encryption should cost only a few bits more");
    }

    #[test]
    fn comparisons_on_public_key_ciphertexts_fit_the_budget() {
        let (ev, secret, pk, ek, _) = setup();
        let mut rng = thread_rng();
        let sk = secret.secret_key();
        let x = vec![0, 0, 1, 4095, 4095, 0, 7, 8, 100, 99, 5, 4094, 4095, 1, 4000, 3];
        let y = vec![0, 1, 0, 4095, 0, 4095, 8, 7, 99, 100, 5, 4095, 4094, 1, 4001, 3];
        let cx = pk.encrypt(&ev, &ev.plaintext_encode(&x, Encoding::default()), &mut rng);
        let cy = pk.encrypt(&ev, &ev.plaintext_encode(&y, Encoding::default()), &mut rng);

        let bits = ev.plaintext_decode(&ev.decrypt(&sk, &univariate_less_than(&ev, &cx, &cy, &ek)), Encoding::default());
        let want: Vec<u64> = x.iter().zip(&y).map(|(a, b)| (a < b) as u64).collect();
        assert_eq!(bits, want);

        let table = LtTable::shipped(4096).unwrap();
        let three = compare_ranged(&ev, &cx, &cy, &ek, table);
        let noise = ev.measure_noise(&sk, &three);
        assert!(noise < 540, "only {} bits left", 600 - noise as i64);
    }

    #[test]
    fn any_two_parties_decrypt_and_one_cannot() {
        let (ev, secret, pk, ek, shares) = setup();
        let mut rng = thread_rng();
        let x = vec![10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160];
        let y = vec![15, 20, 25, 45, 50, 55, 75, 80, 85, 105, 110, 115, 135, 140, 145, 165];
        let cx = pk.encrypt(&ev, &ev.plaintext_encode(&x, Encoding::default()), &mut rng);
        let cy = pk.encrypt(&ev, &ev.plaintext_encode(&y, Encoding::default()), &mut rng);
        let table = LtTable::shipped(4096).unwrap();
        let ct = compare_ranged(&ev, &cx, &cy, &ek, table);
        let reference = ev.plaintext_decode(&ev.decrypt(&secret.secret_key(), &ct), Encoding::default());

        for (i, j) in [(0, 1), (1, 2), (0, 2), (2, 1)] {
            let pi = shares[i].partial_decrypt(&ev, &ct, j, SMUDGE, &mut rng);
            let pj = shares[j].partial_decrypt(&ev, &ct, i, SMUDGE, &mut rng);
            assert_eq!(combine(&ev, &ct, &[pi, pj]), reference, "parties {i} and {j}");
        }

        // One party's contribution alone, padded with a zero partial, is not the plaintext.
        let alone = shares[0].partial_decrypt(&ev, &ct, 1, SMUDGE, &mut rng);
        let nothing = Partial { party: 1, partner: 0, poly: ctx(&ev).zero(Representation::Evaluation) };
        assert_ne!(combine(&ev, &ct, &[alone, nothing]), reference);
    }
}
