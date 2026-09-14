//! Regenerates `data/less_than.bin`, the coefficient table `univariate_less_than` embeds.
//! Only needed if the plaintext modulus changes. Takes a few minutes: it is a t/2-term sum
//! for each of (t-1)/2 coefficients.

fn main() {
    operators::compute_lt_coefficients(65537);
}
