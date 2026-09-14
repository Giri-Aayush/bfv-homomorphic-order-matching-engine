//! Table generator. With no arguments, regenerates `data/less_than.bin`, the coefficient
//! table `univariate_less_than` embeds; only needed if the plaintext modulus changes, and
//! takes a few minutes. With `ranged <R>`, writes `data/lt-h-<R>.bin` for `compare_ranged`,
//! which is O(R²) and takes seconds. Both write under `./data/` of the working directory,
//! so run from `order-match-engine/`, which is where the crate embeds them from.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => {
            operators::compute_lt_coefficients(65537);
        }
        [cmd, range] if cmd == "ranged" => {
            let range: u64 = range.parse().expect("range must be an integer");
            operators::ranged::LtTable::for_range(65537, range).store_h();
        }
        _ => {
            eprintln!("usage: operators [ranged <R>]");
            std::process::exit(2)
        }
    }
}
