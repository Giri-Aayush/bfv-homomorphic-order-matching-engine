//! Collective key generation: no dealer, no party ever holds the secret.
//!
//! After Mouchet, Troncoso-Pastoriza, Bossuat and Hubaux, "Multiparty Homomorphic
//! Encryption from Ring-Learning-with-Errors", PoPETs 2021. Each party samples its own
//! small secret s_i and the joint secret is s = Σ s_i, which nobody computes. Every key is a
//! sum of published contributions over a common random string that all parties derive
//! from one agreed seed.
//!
//! - Public key, one round: party i publishes −a·s_i + e_i. Sum: (−a·s + e, a).
//! - Galois key for exponent g, one round, per digit j: party i publishes
//!   g_j·s_i(x^g) + e − a_j·s_i. Sum: g_j·s(x^g) + e − a_j·s, a key for s(x^g) under s.
//! - Relinearization key, two rounds, per digit j. Round one, with an ephemeral u_i:
//!   h0 = −u_i·a_j + g_j·s_i + e and h1 = s_i·a_j + e. Round two, on the sums:
//!   h0' = s_i·h0 + e and h1' = (u_i − s_i)·h1 + e. The key is (Σh0' + Σh1', Σh1), and
//!   c0 + c1·s = g_j·s² + noise, which is what the library's own generator produces.
//! - Decryption shares: each party splits its own s_i three ways additively and sends part
//!   p to the two parties that hold part p. A party's share of the joint secret is the sum of
//!   what it received, so the replicated 2-of-3 layout in `roles` applies unchanged.
//!
//! The relinearization protocol is the paper's Protocol 2 line for line. The paper's model
//! is passive (semi-honest): a party that publishes a wrong contribution breaks the key,
//! and nothing here detects that. Its smudging is Gaussian with variance 2^λ·σ_ct², tracked
//! per ciphertext; `roles` uses a fixed uniform 2^520 sized to the noisiest measured
//! ciphertext instead. The parties must agree on the seed for the common random string,
//! which the paper says any keyed PRF can provide in the passive model and which in
//! practice comes from a beacon or a hash of commitments. Correctness is tested here.
//! Security is the paper's, and nothing here re-proves it.

use bfv::{
    rot_to_galois_element, EvaluationKey, Evaluator, GaloisKey, HybridKeySwitchingKey, Poly, PolyType,
    RelinearizationKey, Representation, Substitution,
};
use rand::{CryptoRng, Rng, RngCore};

use crate::roles::{PublicKey, Share};

/// The one thing all parties must agree on: the seed of the common random string.
pub type Seed = [u8; 32];

fn q_ctx(ev: &Evaluator) -> bfv::PolyContext<'_> {
    ev.params().poly_ctx(&PolyType::Q, 0)
}
fn qp_ctx(ev: &Evaluator) -> bfv::PolyContext<'_> {
    ev.params().poly_ctx(&PolyType::QP, 0)
}
fn gaussian<R: CryptoRng + RngCore>(ctx: &bfv::PolyContext<'_>, variance: usize, rng: &mut R) -> Poly {
    let mut e = ctx.random_gaussian(Representation::Coefficient, variance, rng);
    ctx.change_representation(&mut e, Representation::Evaluation);
    e
}
fn small(ctx: &bfv::PolyContext<'_>, coefficients: &[i64]) -> Poly {
    let mut p = ctx.try_convert_from_i64_small(coefficients, Representation::Coefficient);
    ctx.change_representation(&mut p, Representation::Evaluation);
    p
}
fn sum(ctx: &bfv::PolyContext<'_>, polys: impl IntoIterator<Item = Poly>) -> Poly {
    let mut it = polys.into_iter();
    let mut acc = it.next().expect("at least one contribution");
    for p in it {
        ctx.add_assign(&mut acc, &p);
    }
    acc
}

/// The common random string: `a` for the public key in Q, and one `a_j` per digit in QP.
pub struct Crs {
    a: Poly,
    digits: Vec<Poly>,
}

impl Crs {
    pub fn from_seed(ev: &Evaluator, seed: Seed) -> Crs {
        let q = q_ctx(ev);
        let qp = qp_ctx(ev);
        let mut a = q.random_with_seed(seed);
        q.change_representation(&mut a, Representation::Evaluation);
        let dnum = ev.params().hybrid_key_switching_params_at_level(0).dnum();
        let mut digits = HybridKeySwitchingKey::generate_c1(dnum, &qp, seed);
        for d in digits.iter_mut() {
            qp.change_representation(d, Representation::Evaluation);
        }
        Crs { a, digits }
    }
}

/// The gadget as constant polynomials in QP, one per digit, so g_j·x is a pointwise multiply
/// in evaluation form. Only the constant coefficient is g_j: a polynomial with g_j in every
/// coefficient is g_j·(1 + x + ... + x^(n−1)), which is not constant once transformed.
fn gadget(ev: &Evaluator) -> Vec<Poly> {
    let qp = qp_ctx(ev);
    let n = ev.params().degree;
    ev.params()
        .hybrid_key_switching_params_at_level(0)
        .gadget()
        .iter()
        .map(|g| {
            let mut coefficients = vec![num_bigint::BigUint::default(); n];
            coefficients[0] = g.clone();
            let mut p = qp.try_convert_from_biguint(&coefficients, Representation::Coefficient);
            qp.change_representation(&mut p, Representation::Evaluation);
            p
        })
        .collect()
}

/// One party. Holds its own secret, as a polynomial in Q and in QP, and nothing of anyone
/// else's. The ephemeral value lives between the two relinearization rounds.
pub struct Party {
    s_q: Poly,
    s_qp: Poly,
    ephemeral: Option<Poly>,
}

impl Party {
    pub fn new<R: CryptoRng + RngCore>(ev: &Evaluator, rng: &mut R) -> Party {
        let n = ev.params().degree;
        let mut secret = vec![0i64; n];
        let mut free: Vec<usize> = (0..n).collect();
        for _ in 0..ev.params().hw {
            let pick = rng.gen_range(0..free.len());
            let index = free.swap_remove(pick);
            secret[index] = if rng.gen::<bool>() { 1 } else { -1 };
        }
        let s_q = small(&q_ctx(ev), &secret);
        let s_qp = small(&qp_ctx(ev), &secret);
        Party { s_q, s_qp, ephemeral: None }
    }

    /// −a·s_i + e_i
    pub fn public_key_share<R: CryptoRng + RngCore>(&self, ev: &Evaluator, crs: &Crs, rng: &mut R) -> Poly {
        let q = q_ctx(ev);
        let mut p = q.mul(&crs.a, &self.s_q);
        q.neg_assign(&mut p);
        q.add_assign(&mut p, &gaussian(&q, ev.params().variance, rng));
        p
    }

    /// Per digit: g_j·s_i(x^exponent) + e − a_j·s_i
    pub fn galois_share<R: CryptoRng + RngCore>(&self, ev: &Evaluator, crs: &Crs, exponent: usize, rng: &mut R) -> Vec<Poly> {
        let qp = qp_ctx(ev);
        let substituted = qp.substitute(&self.s_qp, &Substitution::new(exponent, ev.params().degree));
        gadget(ev)
            .iter()
            .zip(&crs.digits)
            .map(|(g, a)| {
                let mut c0 = qp.mul(g, &substituted);
                qp.add_assign(&mut c0, &gaussian(&qp, ev.params().variance, rng));
                qp.sub_assign(&mut c0, &qp.mul(a, &self.s_qp));
                c0
            })
            .collect()
    }

    /// Round one: (h0, h1) per digit, keeping the ephemeral u_i for round two.
    pub fn relin_round1<R: CryptoRng + RngCore>(&mut self, ev: &Evaluator, crs: &Crs, rng: &mut R) -> (Vec<Poly>, Vec<Poly>) {
        let qp = qp_ctx(ev);
        let n = ev.params().degree;
        let u_coeffs: Vec<i64> = (0..n).map(|_| rng.gen_range(-1i64..=1)).collect();
        let u = small(&qp, &u_coeffs);
        let variance = ev.params().variance;
        let (h0, h1) = gadget(ev)
            .iter()
            .zip(&crs.digits)
            .map(|(g, a)| {
                // h0 = −u·a + g·s + e
                let mut h0 = qp.mul(&u, a);
                qp.neg_assign(&mut h0);
                qp.add_assign(&mut h0, &qp.mul(g, &self.s_qp));
                qp.add_assign(&mut h0, &gaussian(&qp, variance, rng));
                // h1 = s·a + e
                let mut h1 = qp.mul(&self.s_qp, a);
                qp.add_assign(&mut h1, &gaussian(&qp, variance, rng));
                (h0, h1)
            })
            .unzip();
        self.ephemeral = Some(u);
        (h0, h1)
    }

    /// Round two, on the summed h0 and h1: (s_i·h0 + e, (u_i − s_i)·h1 + e) per digit.
    pub fn relin_round2<R: CryptoRng + RngCore>(&self, ev: &Evaluator, h0: &[Poly], h1: &[Poly], rng: &mut R) -> (Vec<Poly>, Vec<Poly>) {
        let qp = qp_ctx(ev);
        let u = self.ephemeral.as_ref().expect("round one first");
        let mut u_minus_s = u.clone();
        qp.sub_assign(&mut u_minus_s, &self.s_qp);
        let variance = ev.params().variance;
        h0.iter()
            .zip(h1)
            .map(|(h0, h1)| {
                let mut a = qp.mul(&self.s_qp, h0);
                qp.add_assign(&mut a, &gaussian(&qp, variance, rng));
                let mut b = qp.mul(&u_minus_s, h1);
                qp.add_assign(&mut b, &gaussian(&qp, variance, rng));
                (a, b)
            })
            .unzip()
    }

    /// An additive three-way split of this party's own secret, to send out.
    pub fn secret_parts<R: CryptoRng + RngCore>(&self, ev: &Evaluator, rng: &mut R) -> [Poly; 3] {
        let q = q_ctx(ev);
        let p0 = q.random(Representation::Evaluation, rng);
        let p1 = q.random(Representation::Evaluation, rng);
        let mut p2 = self.s_q.clone();
        q.sub_assign(&mut p2, &p0);
        q.sub_assign(&mut p2, &p1);
        [p0, p1, p2]
    }
}

/// The keys three parties produce together.
pub struct Collective {
    pub pk: PublicKey,
    pub ek: EvaluationKey,
    pub shares: [Share; 3],
}

/// Run the protocols with three fresh parties in one process. Every step is a sum of
/// published values, so splitting it across processes changes where the sums happen, not
/// what they are.
pub fn setup<R: CryptoRng + RngCore>(ev: &Evaluator, rotations: &[isize], seed: Seed, rng: &mut R) -> Collective {
    let mut parties: Vec<Party> = (0..3).map(|_| Party::new(ev, rng)).collect();
    run(ev, &mut parties, rotations, seed, rng)
}

/// The protocols, for a given set of three parties.
pub fn run<R: CryptoRng + RngCore>(ev: &Evaluator, parties: &mut [Party], rotations: &[isize], seed: Seed, rng: &mut R) -> Collective {
    assert_eq!(parties.len(), 3, "the replicated 2-of-3 layout needs exactly three parties");
    let q = q_ctx(ev);
    let qp = qp_ctx(ev);
    let n = ev.params().degree;
    let crs = Crs::from_seed(ev, seed);

    // public key
    let p0 = sum(&q, parties.iter().map(|p| p.public_key_share(ev, &crs, rng)));
    let pk = PublicKey::from_parts(p0, crs.a.clone());

    // Galois keys, one per rotation index
    let rtgs: Vec<((isize, usize), GaloisKey)> = rotations
        .iter()
        .map(|&index| {
            let exponent = rot_to_galois_element(index, n);
            let shares: Vec<Vec<Poly>> = parties.iter().map(|p| p.galois_share(ev, &crs, exponent, rng)).collect();
            let c0s: Vec<Poly> = (0..crs.digits.len())
                .map(|j| sum(&qp, shares.iter().map(|s| s[j].clone())))
                .collect();
            let ksk = HybridKeySwitchingKey::from_parts(c0s, crs.digits.clone());
            ((index, 0), GaloisKey::from_ksk(exponent, n, ksk, 0))
        })
        .collect();

    // relinearization key, two rounds
    let round1: Vec<(Vec<Poly>, Vec<Poly>)> = parties.iter_mut().map(|p| p.relin_round1(ev, &crs, rng)).collect();
    let digits = crs.digits.len();
    let h0: Vec<Poly> = (0..digits).map(|j| sum(&qp, round1.iter().map(|(h0, _)| h0[j].clone()))).collect();
    let h1: Vec<Poly> = (0..digits).map(|j| sum(&qp, round1.iter().map(|(_, h1)| h1[j].clone()))).collect();
    let round2: Vec<(Vec<Poly>, Vec<Poly>)> = parties.iter().map(|p| p.relin_round2(ev, &h0, &h1, rng)).collect();
    let c0s: Vec<Poly> = (0..digits)
        .map(|j| {
            let mut c0 = sum(&qp, round2.iter().map(|(a, _)| a[j].clone()));
            qp.add_assign(&mut c0, &sum(&qp, round2.iter().map(|(_, b)| b[j].clone())));
            c0
        })
        .collect();
    let rlk = RelinearizationKey::from_ksk(HybridKeySwitchingKey::from_parts(c0s, h1), 0);
    let ek = EvaluationKey::from_parts(vec![(0, rlk)], rtgs);

    // decryption shares: part p of the joint secret is the sum of every party's part p
    let parts: Vec<[Poly; 3]> = parties.iter().map(|p| p.secret_parts(ev, rng)).collect();
    let joint = |p: usize| sum(&q, parts.iter().map(|ps| ps[p].clone()));
    let shares = [
        Share::from_parts(0, [joint(0), joint(1)]),
        Share::from_parts(1, [joint(1), joint(2)]),
        Share::from_parts(2, [joint(2), joint(0)]),
    ];

    Collective { pk, ek, shares }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packed::{broadcast_sum, prefix_sum, rotation_indices};
    use crate::ranged::{compare_ranged, LtTable};
    use crate::roles::combine;
    use bfv::{BfvParameters, Ciphertext, Encoding, SecretKey};
    use rand::thread_rng;

    /// Decrypt against the joint secret directly through the ring, independently of the
    /// share machinery. The library's SecretKey refuses coefficients outside {-1, 0, 1}
    /// and the joint secret is a sum of three, so this goes through the same null-key
    /// decode as `combine`.
    fn decrypt_joint(ev: &Evaluator, ct: &Ciphertext, parties: &[Party]) -> Vec<u64> {
        let q = q_ctx(ev);
        let s = sum(&q, parties.iter().map(|p| p.s_q.clone()));
        let mut c1 = ct.c_ref()[1].clone();
        q.change_representation(&mut c1, Representation::Evaluation);
        let mut m = ct.c_ref()[0].clone();
        q.change_representation(&mut m, Representation::Evaluation);
        q.add_assign(&mut m, &q.mul(&c1, &s));
        q.change_representation(&mut m, Representation::Coefficient);
        let zero = q.zero(Representation::Coefficient);
        let n = ev.params().degree;
        let null = SecretKey::new(vec![0; n], n);
        ev.plaintext_decode(&ev.decrypt(&null, &Ciphertext::new(vec![m, zero], PolyType::Q, 0)), Encoding::default())
    }

    fn evaluator() -> Evaluator {
        let mut params = BfvParameters::new(&[60; 10], 65537, 1 << 4);
        params.enable_hybrid_key_switching(&[60; 3]);
        Evaluator::new(params)
    }

    /// Runs the protocol but keeps the parties, so tests can decrypt against the joint secret.
    fn setup_keeping_parties(ev: &Evaluator, rotations: &[isize]) -> (Collective, Vec<Party>) {
        let mut rng = thread_rng();
        let mut parties: Vec<Party> = (0..3).map(|_| Party::new(ev, &mut rng)).collect();
        let c = run(ev, &mut parties, rotations, [7u8; 32], &mut rng);
        (c, parties)
    }

    #[test]
    fn collective_public_key_encrypts_for_the_joint_secret() {
        let ev = evaluator();
        let (c, parties) = setup_keeping_parties(&ev, &[]);
        let mut rng = thread_rng();
        let m: Vec<u64> = (0..16).map(|i| i * 1000 + 3).collect();
        let ct = c.pk.encrypt(&ev, &ev.plaintext_encode(&m, Encoding::default()), &mut rng);
        assert_eq!(decrypt_joint(&ev, &ct, &parties), m);

        // any one party's own secret is not the joint secret
        assert_ne!(decrypt_joint(&ev, &ct, &parties[..1]), m);
    }

    #[test]
    fn collective_galois_keys_rotate() {
        let ev = evaluator();
        let rots = rotation_indices(&ev);
        let (c, parties) = setup_keeping_parties(&ev, &rots);
        let mut rng = thread_rng();
        let m: Vec<u64> = (0..16).collect();
        let ct = c.pk.encrypt(&ev, &ev.plaintext_encode(&m, Encoding::default()), &mut rng);
        let out = decrypt_joint(&ev, &ev.rotate(&ct, -1, &c.ek), &parties);
        assert_eq!(out, vec![7, 0, 1, 2, 3, 4, 5, 6, 15, 8, 9, 10, 11, 12, 13, 14]);
    }

    #[test]
    fn collective_relinearization_key_relinearizes_a_product() {
        let ev = evaluator();
        let (c, parties) = setup_keeping_parties(&ev, &[]);
        let mut rng = thread_rng();
        let x: Vec<u64> = (0..16).map(|i| i + 2).collect();
        let y: Vec<u64> = (0..16).map(|i| 100 + i).collect();
        let cx = c.pk.encrypt(&ev, &ev.plaintext_encode(&x, Encoding::default()), &mut rng);
        let cy = c.pk.encrypt(&ev, &ev.plaintext_encode(&y, Encoding::default()), &mut rng);
        let product = ev.relinearize(&ev.mul(&cx, &cy), &c.ek);
        assert_eq!(product.c_ref().len(), 2);
        let want: Vec<u64> = x.iter().zip(&y).map(|(a, b)| a * b).collect();
        assert_eq!(decrypt_joint(&ev, &product, &parties), want);
    }

    #[test]
    fn a_full_packed_step_with_collective_keys_and_threshold_decryption() {
        let ev = evaluator();
        let rots = rotation_indices(&ev);
        let (c, parties) = setup_keeping_parties(&ev, &rots);
        let mut rng = thread_rng();
        let buys = vec![1250, 3400, 800, 2900, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let sells = vec![2000, 1100, 450, 1900, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let cb = c.pk.encrypt(&ev, &ev.plaintext_encode(&buys, Encoding::default()), &mut rng);
        let cs = c.pk.encrypt(&ev, &ev.plaintext_encode(&sells, Encoding::default()), &mut rng);
        let prefix = prefix_sum(&ev, &cb, &c.ek);
        let total = broadcast_sum(&ev, &cs, &c.ek);
        let table = LtTable::shipped(8351).unwrap();
        let over = compare_ranged(&ev, &total, &prefix, &c.ek, table);

        let reference = decrypt_joint(&ev, &over, &parties);
        // prefixes 1250 4650 5450 8350 against 5450: over at the last, equal at the third
        assert_eq!(&reference[..4], &[0, 0, table.equal_marker(), 1]);

        let pa = c.shares[1].partial_decrypt(&ev, &over, 2, 520, &mut rng);
        let pb = c.shares[2].partial_decrypt(&ev, &over, 1, 520, &mut rng);
        assert_eq!(combine(&ev, &over, &[pa, pb]), reference);
    }
}

