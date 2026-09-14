use bfv::{BfvParameters, Ciphertext, Encoding, EvaluationKey, Evaluator, SecretKey};
use operators::univariate_less_than;
use rand::rngs::ThreadRng;
use rand::thread_rng;
use serde::Deserialize;
use std::collections::HashSet;
use std::time::Instant;

/// Plaintext modulus. A Fermat prime, which the comparison circuit relies on.
const T: u64 = 65537;
/// Ring degree. This is the library's floor and offers no lattice security; see README.
const SLOTS: usize = 1 << 4;

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
}

/// Everything that can touch a key lives here. The operators crate only ever sees `ek`.
struct Engine {
    evaluator: Evaluator,
    sk: SecretKey,
    ek: EvaluationKey,
    rng: ThreadRng,
    comparisons: usize,
    decryptions: usize,
}

impl Engine {
    fn new() -> Self {
        let mut rng = thread_rng();
        let mut params = BfvParameters::new(&[60; 10], T, SLOTS);
        params.enable_hybrid_key_switching(&[60; 3]);
        let sk = SecretKey::random_with_params(&params, &mut rng);
        let evaluator = Evaluator::new(params);
        // Relinearization at level 0 is all the comparison circuit needs. No rotation keys.
        let ek = EvaluationKey::new(evaluator.params(), &sk, &[0], &[], &[], &mut rng);
        Engine { evaluator, sk, ek, rng, comparisons: 0, decryptions: 0 }
    }

    /// Encrypt one quantity into slot 0.
    fn encrypt(&mut self, quantity: u64) -> Ciphertext {
        let mut slots = vec![0u64; SLOTS];
        slots[0] = quantity;
        let pt = self.evaluator.plaintext_encode(&slots, Encoding::default());
        self.evaluator.encrypt(&self.sk, &pt, &mut self.rng)
    }

    /// The only way a value leaves the encrypted domain. Counted so the run can report it.
    fn decrypt(&mut self, ct: &Ciphertext) -> u64 {
        self.decryptions += 1;
        let pt = self.evaluator.decrypt(&self.sk, ct);
        self.evaluator.plaintext_decode(&pt, Encoding::default())[0]
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
    let book = Book {
        pair: file.pair,
        buys: to_orders("B", file.buy_orders),
        sells: to_orders("S", file.sell_orders),
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
    let Book { pair, buys: buy_orders, sells: sell_orders } = read_book(path);

    println!();
    println!("bfv order matching   {pair}   {} buys, {} sells   {path}", buy_orders.len(), sell_orders.len());
    println!("params               n={SLOTS}  t={T}  Q=10x60-bit  P=3x60-bit   (toy degree, see README)");
    println!();

    let mut engine = Engine::new();
    phase("keys", "secret key and evaluation key", &mut clock, "");

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
    let path = std::env::args().nth(1).unwrap_or_else(|| "order.json".to_string());
    match_book(&path);
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
    fn equal_remainder_does_not_fill() {
        assert_eq!(
            match_book("books/equal-remainder.json"),
            Report { matched: 300, smaller_total: 500, comparisons: 4, fills_decrypted: 3, unfilled: 2 }
        );
    }
}
