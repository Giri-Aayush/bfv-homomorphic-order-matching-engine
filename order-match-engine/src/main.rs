mod packed;

use bfv::{BfvParameters, Ciphertext, Encoding, EvaluationKey, Evaluator};
use operators::roles::{combine, PublicKey, Secret, Share};
use operators::univariate_less_than;
use rand::rngs::ThreadRng;
use rand::thread_rng;
use serde::Deserialize;
use std::collections::HashSet;
use std::time::Instant;

/// Plaintext modulus. A Fermat prime, which the comparison circuit relies on.
const T: u64 = 65537;
/// Toy ring degree: the library's floor, no lattice security, fast enough to iterate on.
const TOY_DEGREE: usize = 1 << 4;
/// The largest degree batching allows at this t, since t − 1 = 2^16 must be a multiple of
/// 2n. With log2(QP) = 780 and a ternary secret of weight n/2 this is roughly 128-bit; see
/// README for the caveat on the secret's weight.
const SECURE_DEGREE: usize = 1 << 15;
/// Uniform noise each decrypting party adds to its partial. It has to dwarf the ciphertext's
/// own noise, at most about 470 bits after a ranged comparison at n = 2^15, by a statistical
/// margin, and two of them still have to sit well under Δ/2 ≈ 2^583 for decoding to round
/// correctly. 520 leaves about 50 bits on each side.
const SMUDGE_BITS: u64 = 520;

/// An order in the book file: either a bare quantity or `{"id": "...", "qty": N}`.
/// Ids are not secret and appear in the report. Quantities are the values that get encrypted.
#[derive(Deserialize)]
#[serde(untagged)]
enum OrderSpec {
    Quantity(u64),
    Tagged { id: String, qty: u64 },
}

impl OrderSpec {
    fn into_order(self, side: &str, index: usize) -> Order {
        match self {
            OrderSpec::Quantity(qty) => Order { id: format!("{side}-{}", index + 1), qty },
            OrderSpec::Tagged { id, qty } => Order { id, qty },
        }
    }
}

struct Order {
    id: String,
    qty: u64,
}

#[derive(Deserialize)]
struct BookFile {
    pair: String,
    buy_orders: Vec<OrderSpec>,
    sell_orders: Vec<OrderSpec>,
}

struct Book {
    pair: String,
    buys: Vec<Order>,
    sells: Vec<Order>,
    /// One more than the largest side total. Every comparison operand is below it, which
    /// lets the packed matcher pick a comparison circuit sized to the book.
    range: u64,
}

/// Three roles in one process, kept apart by what each can do. Submitters encrypt with the
/// public key. The matcher computes with the evaluation key and can decrypt nothing. Each
/// decryption needs two of the three shares. No secret key exists after setup.
struct Engine {
    evaluator: Evaluator,
    pk: PublicKey,
    ek: EvaluationKey,
    shares: [Share; 3],
    rng: ThreadRng,
    degree: usize,
    comparisons: usize,
    decryptions: usize,
}

impl Engine {
    /// The sequential walk needs relinearization at level 0 and nothing else. The packed
    /// matcher also needs the rotation keys behind prefix sums and broadcast totals.
    fn new(with_rotations: bool, degree: usize) -> Self {
        let mut rng = thread_rng();
        let mut params = BfvParameters::new(&[60; 10], T, degree);
        params.enable_hybrid_key_switching(&[60; 3]);
        let evaluator = Evaluator::new(params);
        let rotations = if with_rotations { operators::packed::rotation_indices(&evaluator) } else { vec![] };
        let (pk, ek, shares) = Self::deal(&evaluator, &rotations, &mut rng);
        Engine { evaluator, pk, ek, shares, rng, degree, comparisons: 0, decryptions: 0 }
    }

    /// The dealer. The secret lives only inside this function: it derives the public and
    /// evaluation keys, splits itself three ways, and is dropped on return.
    fn deal(evaluator: &Evaluator, rotations: &[isize], rng: &mut ThreadRng) -> (PublicKey, EvaluationKey, [Share; 3]) {
        let secret = Secret::generate(evaluator.params(), rng);
        let sk = secret.secret_key();
        let levels = vec![0; rotations.len()];
        let ek = EvaluationKey::new(evaluator.params(), &sk, &[0], &levels, rotations, rng);
        let pk = secret.public_key(evaluator, rng);
        let shares = secret.split(evaluator, rng);
        (pk, ek, shares)
    }

    fn params_line(&self) -> String {
        let note = if self.degree == SECURE_DEGREE { "roughly 128-bit, see README" } else { "toy degree, see README" };
        format!("params               n={}  t={T}  Q=10x60-bit  P=3x60-bit   ({note})", self.degree)
    }

    /// Encrypt one quantity into slot 0.
    fn encrypt(&mut self, quantity: u64) -> Ciphertext {
        self.encrypt_lane(&[quantity])
    }

    /// Encrypt up to a lane of quantities, one per slot from slot 0, under the public key.
    fn encrypt_lane(&mut self, quantities: &[u64]) -> Ciphertext {
        let mut slots = vec![0u64; self.degree];
        slots[..quantities.len()].copy_from_slice(quantities);
        let pt = self.evaluator.plaintext_encode(&slots, Encoding::default());
        self.pk.encrypt(&self.evaluator, &pt, &mut self.rng)
    }

    /// The only way a value leaves the encrypted domain. Counted so the run can report it.
    fn decrypt(&mut self, ct: &Ciphertext) -> u64 {
        self.decrypt_slots(ct)[0]
    }

    /// Same boundary crossing, all slots: two of the three parties each compute a partial
    /// and the combiner adds them. Which pair rotates per decryption, so a run exercises all
    /// three. One decryption however many slots are read.
    fn decrypt_slots(&mut self, ct: &Ciphertext) -> Vec<u64> {
        let (a, b) = Self::pair(self.decryptions);
        self.decryptions += 1;
        let pa = self.shares[a].partial_decrypt(&self.evaluator, ct, b, SMUDGE_BITS, &mut self.rng);
        let pb = self.shares[b].partial_decrypt(&self.evaluator, ct, a, SMUDGE_BITS, &mut self.rng);
        combine(&self.evaluator, ct, &[pa, pb])
    }

    fn pair(k: usize) -> (usize, usize) {
        [(0, 1), (1, 2), (2, 0)][k % 3]
    }

    fn sum(&self, cts: &[Ciphertext]) -> Ciphertext {
        cts[1..]
            .iter()
            .fold(cts[0].clone(), |acc, ct| self.evaluator.add(&acc, ct))
    }

    /// Homomorphic x < y, then decrypt the single result bit so control flow can branch on it.
    fn less_than(&mut self, x: &Ciphertext, y: &Ciphertext) -> bool {
        let bit_ct = univariate_less_than(&self.evaluator, x, y, &self.ek);
        self.comparisons += 1;
        match self.decrypt(&bit_ct) {
            0 => false,
            1 => true,
            other => panic!("comparison circuit returned {other}, not a bit: noise budget exceeded or parameters changed"),
        }
    }
}

fn fail(msg: String) -> ! {
    eprintln!("{msg}");
    std::process::exit(2)
}

/// Load a book and check it against the comparison circuit's input domain. These are the
/// submitter's checks, done on plaintext the submitter already holds, before anything is
/// encrypted.
fn read_book(path: &str) -> Book {
    let contents = std::fs::read_to_string(path)
        .unwrap_or_else(|e| fail(format!("could not read {path}: {e}")));
    let file: BookFile = serde_json::from_str(&contents)
        .unwrap_or_else(|e| fail(format!("could not parse {path}: {e}")));
    let to_orders = |side: &str, specs: Vec<OrderSpec>| -> Vec<Order> {
        specs.into_iter().enumerate().map(|(i, o)| o.into_order(side, i)).collect()
    };
    let mut book = Book {
        pair: file.pair,
        buys: to_orders("B", file.buy_orders),
        sells: to_orders("S", file.sell_orders),
        range: 0,
    };

    let bound = T / 2;
    let mut ids = HashSet::new();
    for (side, orders) in [("buy", &book.buys), ("sell", &book.sells)] {
        if orders.is_empty() {
            fail(format!("{path}: the {side} side is empty"));
        }
        for o in orders {
            if o.qty == 0 {
                fail(format!("{path}: {} has quantity 0", o.id));
            }
            if !ids.insert(o.id.as_str()) {
                fail(format!("{path}: duplicate order id {}", o.id));
            }
        }
        // univariate_less_than is only correct for operands below t/2, and the side totals
        // are operands. Refuse a book that would silently produce wrong bits.
        let total: u64 = orders.iter().map(|o| o.qty).sum();
        if total >= bound {
            fail(format!(
                "{path}: {side} side totals {total}, but the comparison circuit is only correct below t/2 = {bound}"
            ));
        }
        book.range = book.range.max(total + 1);
    }
    book
}

/// One line per phase: what happened, how long it took, and anything worth noting.
fn phase(name: &str, detail: &str, clock: &mut Instant, note: &str) {
    let secs = clock.elapsed().as_secs_f64();
    *clock = Instant::now();
    if note.is_empty() {
        println!("  {name:<10}{detail:<52}{secs:>5.2} s");
    } else {
        println!("  {name:<10}{detail:<52}{secs:>5.2} s   {note}");
    }
}

/// One side of the book after encryption: ids in the clear, quantities as ciphertexts.
struct Side<'a> {
    name: &'static str,
    ids: &'a [String],
    orders: &'a [Ciphertext],
}

/// What a run produced, and what it cost. Everything the tests pin.
#[derive(Debug, PartialEq, Eq)]
struct Report {
    matched: u64,
    smaller_total: u64,
    comparisons: usize,
    fills_decrypted: usize,
    unfilled: usize,
}

fn match_book(path: &str) -> Report {
    let started = Instant::now();
    let mut clock = Instant::now();
    let Book { pair, buys: buy_orders, sells: sell_orders, .. } = read_book(path);

    let mut engine = Engine::new(false, TOY_DEGREE);
    println!();
    println!("bfv order matching   {pair}   {} buys, {} sells   {path}", buy_orders.len(), sell_orders.len());
    println!("{}", engine.params_line());
    println!();
    phase("keys", "pk, ek, secret split 2-of-3 and dropped", &mut clock, "");

    // Ids stay in the clear. Quantities are encrypted and the plaintext copies dropped, so from
    // here on the only way back to a quantity is a decryption.
    let (buy_ids, buys): (Vec<String>, Vec<Ciphertext>) = buy_orders
        .into_iter()
        .map(|o| (o.id, engine.encrypt(o.qty)))
        .unzip();
    let (sell_ids, sells): (Vec<String>, Vec<Ciphertext>) = sell_orders
        .into_iter()
        .map(|o| (o.id, engine.encrypt(o.qty)))
        .unzip();
    phase("encrypt", &format!("{} quantities, plaintext inputs dropped", buys.len() + sells.len()), &mut clock, "");

    let buy_sum = engine.sum(&buys);
    let sell_sum = engine.sum(&sells);
    phase("sum", "Σbuys and Σsells, homomorphic, never decrypted", &mut clock, "");

    // One bit leaves the encrypted domain: which side is larger.
    let buy_side = Side { name: "buy", ids: &buy_ids, orders: &buys };
    let sell_side = Side { name: "sell", ids: &sell_ids, orders: &sells };
    let (larger, smaller, smaller_sum) = if engine.less_than(&buy_sum, &sell_sum) {
        (sell_side, buy_side, buy_sum)
    } else {
        (buy_side, sell_side, sell_sum)
    };
    phase("compare", "LT(Σbuys, Σsells), one bit decrypted", &mut clock, &format!("{} side is larger", larger.name));

    // Walk the larger side against the encrypted remainder of the smaller side. Each step
    // decrypts one comparison bit. A filled order's quantity is decrypted for the report; an
    // unfilled order's quantity never is.
    println!();
    println!("  walk      {} orders against the encrypted {} remainder", larger.name, smaller.name);
    println!("            {:<10}{:<11}quantity", "order", "result");
    let mut remaining = smaller_sum;
    let mut matched = 0u64;
    let mut unfilled = 0usize;
    for (id, order) in larger.ids.iter().zip(larger.orders) {
        if engine.less_than(order, &remaining) {
            remaining = engine.evaluator.sub(&remaining, order);
            let quantity = engine.decrypt(order);
            matched += quantity;
            println!("            {id:<10}{:<11}{quantity}", "filled");
        } else {
            unfilled += 1;
            println!("            {id:<10}{:<11}never decrypted", "unfilled");
        }
    }
    let walk_secs = clock.elapsed().as_secs_f64();
    println!("            {:>59}", format!("{walk_secs:.2} s"));

    // The smaller side fills entirely. Its quantities are decrypted for the report.
    println!();
    println!("  {:<10}all {} filled", format!("{} side", smaller.name), smaller.orders.len());
    let mut smaller_total = 0u64;
    for (id, order) in smaller.ids.iter().zip(smaller.orders) {
        let quantity = engine.decrypt(order);
        smaller_total += quantity;
        println!("            {id:<21}{quantity}");
    }

    let report = Report {
        matched,
        smaller_total,
        comparisons: engine.comparisons,
        fills_decrypted: engine.decryptions - engine.comparisons,
        unfilled,
    };

    println!();
    println!("  {:<10}{} / {}", "matched", report.matched, report.smaller_total);
    println!("  {:<10}{} comparison bits, {} fill quantities", "revealed", report.comparisons, report.fills_decrypted);
    println!("  {:<10}{} decryptions, each by two of three parties, no single key held", "decrypted", engine.decryptions);
    println!(
        "  {:<10}{} side total, {} unfilled {}",
        "withheld",
        larger.name,
        report.unfilled,
        if report.unfilled == 1 { "quantity" } else { "quantities" }
    );
    println!("  {:<10}{:.2} s, {} comparisons", "elapsed", started.elapsed().as_secs_f64(), report.comparisons);
    println!();

    report
}

fn main() {
    let mut packed = false;
    let mut secure = false;
    let mut path = "order.json".to_string();
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--packed" => packed = true,
            // Secure parameters imply the packed matcher: the walk's full-domain circuit does
            // not fit the noise budget at n = 2^15, and the packed one only needs a table.
            "--secure" => {
                secure = true;
                packed = true;
            }
            "--help" | "-h" => {
                eprintln!("usage: order-match-engine [--packed] [--secure] [book.json]");
                std::process::exit(0)
            }
            other => path = other.to_string(),
        }
    }
    if packed {
        packed::match_book(&path, if secure { SECURE_DEGREE } else { TOY_DEGREE });
    } else {
        match_book(&path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every shipped book, pinned. A change to the circuit, the walk, or the decryption
    // accounting shows up here as a diff in one of these five numbers.

    #[test]
    fn toy_book() {
        assert_eq!(
            match_book("order.json"),
            Report { matched: 18, smaller_total: 21, comparisons: 7, fills_decrypted: 9, unfilled: 3 }
        );
    }

    #[test]
    fn eth_usdc_buy_side_larger() {
        assert_eq!(
            match_book("books/eth-usdc.json"),
            Report { matched: 13715, smaller_total: 13730, comparisons: 12, fills_decrypted: 18, unfilled: 3 }
        );
    }

    #[test]
    fn btc_usdt_sell_side_larger() {
        assert_eq!(
            match_book("books/btc-usdt.json"),
            Report { matched: 2540, smaller_total: 2875, comparisons: 6, fills_decrypted: 8, unfilled: 1 }
        );
    }

    #[test]
    fn small_lots_book() {
        assert_eq!(
            match_book("books/small-lots.json"),
            Report { matched: 2645, smaller_total: 2780, comparisons: 9, fills_decrypted: 13, unfilled: 1 }
        );
    }

    #[test]
    fn equal_remainder_does_not_fill() {
        assert_eq!(
            match_book("books/equal-remainder.json"),
            Report { matched: 300, smaller_total: 500, comparisons: 4, fills_decrypted: 3, unfilled: 2 }
        );
    }
}
