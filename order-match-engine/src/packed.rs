//! Packed matching: a whole side in a few ciphertexts, one order per slot, and one
//! comparison per lane instead of one per order.
//!
//! For each side, cumulative volume is a prefix sum by rotation, the other side's total is
//! broadcast to every slot, and LT(total, prefix) gives a bit per order: 1 where the
//! cumulative volume through that order already exceeds what the other side has. Orders
//! before the first 1 fill whole. The first 1 is the boundary order and fills partially with
//! whatever is left, which is one more masked decryption. Orders after it fill nothing and
//! are never looked at again.
//!
//! That is time priority with partial fills, which is how a venue actually matches, and it
//! reveals less than the sequential walk: one bit vector per lane instead of one bit per
//! order, the boundary order's fill but never its size, and nothing at all about the orders
//! behind it.

use crate::{fail, phase, read_book, Book, Engine, Order, Report, SECURE_DEGREE};
use bfv::Ciphertext;
use operators::packed::{broadcast_sum, lane_len, mask, prefix_sum};
use operators::ranged::{compare_ranged, LtTable};
use operators::univariate_less_than;
use std::time::Instant;

/// A side packed into lanes. Ids stay with their lane so the report can name orders.
struct PackedSide {
    name: &'static str,
    lanes: Vec<Ciphertext>,
    ids: Vec<Vec<String>>,
}

impl PackedSide {
    fn pack(engine: &mut Engine, name: &'static str, orders: Vec<Order>, lane: usize) -> Self {
        let mut lanes = Vec::new();
        let mut ids = Vec::new();
        for chunk in orders.chunks(lane) {
            let qtys: Vec<u64> = chunk.iter().map(|o| o.qty).collect();
            lanes.push(engine.encrypt_lane(&qtys));
            ids.push(chunk.iter().map(|o| o.id.clone()).collect());
        }
        PackedSide { name, lanes, ids }
    }

    fn len(&self) -> usize {
        self.ids.iter().map(Vec::len).sum()
    }

    /// The side's total, broadcast to every slot of the lane, still encrypted.
    fn total(&self, engine: &Engine) -> Ciphertext {
        let mut acc = broadcast_sum(&engine.evaluator, &self.lanes[0], &engine.ek);
        for lane in &self.lanes[1..] {
            let t = broadcast_sum(&engine.evaluator, lane, &engine.ek);
            acc = engine.evaluator.add(&acc, &t);
        }
        acc
    }
}

/// What happened to one order in the packed match.
enum Fill {
    Whole(u64),
    /// How much of the boundary order filled. Its full size stays encrypted.
    Partial(u64),
    None,
}

/// Which comparison circuit a run uses: one sized to the book's range when a shipped table
/// covers it, else the full-domain circuit.
enum Circuit {
    Ranged(&'static LtTable),
    Full,
}

impl Circuit {
    fn for_range(range: u64) -> Self {
        LtTable::shipped(range).map_or(Circuit::Full, Circuit::Ranged)
    }

    fn describe(&self) -> String {
        match self {
            Circuit::Ranged(t) => format!("ranged LT R={}", t.range),
            Circuit::Full => "full LT R=32768".to_string(),
        }
    }

    /// One slot per order: 1 where x < y. The ranged circuit also has an equal marker, and
    /// equal is not less, so both decode the same way. Any other value means the noise
    /// budget was exceeded and the run stops rather than reporting fills that are not real.
    fn less_than(&self, engine: &mut Engine, x: &Ciphertext, y: &Ciphertext, slots: usize) -> Vec<bool> {
        let (ct, legal): (Ciphertext, &[u64]) = match self {
            Circuit::Ranged(t) => (compare_ranged(&engine.evaluator, x, y, &engine.ek, t), &[0, 1, t.equal_marker()]),
            Circuit::Full => (univariate_less_than(&engine.evaluator, x, y, &engine.ek), &[0, 1]),
        };
        engine.comparisons += 1;
        let values = engine.decrypt_slots(&ct);
        if let Some(bad) = values[..slots].iter().find(|v| !legal.contains(v)) {
            fail(format!("comparison returned {bad}, which is not a legal output: noise budget exceeded at n = {}", engine.degree));
        }
        values.into_iter().map(|v| v == 1).collect()
    }
}

/// Match one side against the other side's encrypted total, one comparison per lane.
fn fill_side(engine: &mut Engine, side: &PackedSide, other_total: &Ciphertext, circuit: &Circuit) -> Vec<Fill> {
    let mut fills = Vec::with_capacity(side.len());
    let mut boundary_seen = false;
    // Cumulative volume of the lanes before this one, broadcast, so lane k's prefixes are
    // absolute rather than relative to the lane.
    let mut carry: Option<Ciphertext> = None;

    for (k, lane_ct) in side.lanes.iter().enumerate() {
        let n = side.ids[k].len();
        if boundary_seen {
            // Everything past the boundary is unfilled. Nothing is computed or decrypted
            // for these lanes, so nothing about them is learned.
            fills.extend((0..n).map(|_| Fill::None));
            continue;
        }

        let mut prefix = prefix_sum(&engine.evaluator, lane_ct, &engine.ek);
        if let Some(c) = &carry {
            prefix = engine.evaluator.add(&prefix, c);
        }

        // over[i] where cumulative volume through order i exceeds the other side's total.
        let over = circuit.less_than(engine, other_total, &prefix, n);
        let whole: Vec<bool> = (0..n).map(|i| !over[i]).collect();
        let boundary = (0..n).find(|&i| over[i]);

        // Reveal only the whole fills: mask everything else to zero before decrypting.
        let revealed = engine.decrypt_slots(&mask(&engine.evaluator, lane_ct, &whole));

        // The boundary order fills with what is left: total - prefix before it, which is
        // total - prefix[i] + qty[i]. Masked to that one slot before decrypting.
        let partial = boundary.map(|i| {
            let mut room = engine.evaluator.sub(other_total, &prefix);
            room = engine.evaluator.add(&room, lane_ct);
            let one_hot: Vec<bool> = (0..n).map(|j| j == i).collect();
            engine.decrypt_slots(&mask(&engine.evaluator, &room, &one_hot))[i]
        });

        for (i, &qty) in revealed.iter().take(n).enumerate() {
            fills.push(match boundary {
                Some(b) if i == b => Fill::Partial(partial.unwrap()),
                Some(b) if i > b => Fill::None,
                _ => Fill::Whole(qty),
            });
        }
        boundary_seen = boundary.is_some();

        let lane_total = broadcast_sum(&engine.evaluator, lane_ct, &engine.ek);
        carry = Some(match carry {
            Some(c) => engine.evaluator.add(&c, &lane_total),
            None => lane_total,
        });
    }
    fills
}

fn print_side(side: &PackedSide, fills: &[Fill], against: &str) {
    println!();
    println!("  {:<10}time priority against the {against} total", format!("{} side", side.name));
    println!("            {:<10}{:<11}quantity", "order", "result");
    let ids = side.ids.iter().flatten();
    for (id, fill) in ids.zip(fills) {
        match fill {
            Fill::Whole(q) => println!("            {id:<10}{:<11}{q}", "filled"),
            Fill::Partial(q) => println!("            {id:<10}{:<11}{q} of an undisclosed size", "partial"),
            Fill::None => println!("            {id:<10}{:<11}never decrypted", "unfilled"),
        }
    }
}

pub fn match_book(path: &str, degree: usize) -> Report {
    let started = Instant::now();
    let mut clock = Instant::now();
    let Book { pair, buys, sells, range } = read_book(path);
    let n_buys = buys.len();
    let n_sells = sells.len();
    let circuit = Circuit::for_range(range);
    if degree == SECURE_DEGREE && matches!(circuit, Circuit::Full) {
        fail(format!(
            "{path}: range {range} has no shipped comparison table, and at n = {degree} the full circuit exceeds the noise budget. Build one with `operators ranged <R>`."
        ));
    }

    let mut engine = Engine::new(true, degree);
    let lane = lane_len(&engine.evaluator);
    let rotations = operators::packed::rotation_indices(&engine.evaluator).len();
    println!();
    println!("bfv order matching   {pair}   {n_buys} buys, {n_sells} sells   {path}   packed");
    println!("{}", engine.params_line());
    println!();
    phase("keys", &format!("pk, ek, {rotations} rotation keys, secret split 2-of-3"), &mut clock, "");

    let buy_side = PackedSide::pack(&mut engine, "buy", buys, lane);
    let sell_side = PackedSide::pack(&mut engine, "sell", sells, lane);
    let n_lanes = buy_side.lanes.len() + sell_side.lanes.len();
    phase(
        "pack",
        &format!("{} quantities into {n_lanes} lanes of {lane}, inputs dropped", n_buys + n_sells),
        &mut clock,
        "",
    );

    let buy_total = buy_side.total(&engine);
    let sell_total = sell_side.total(&engine);
    phase("totals", "Σbuys and Σsells by rotation, never decrypted", &mut clock, "");

    let buy_fills = fill_side(&mut engine, &buy_side, &sell_total, &circuit);
    let sell_fills = fill_side(&mut engine, &sell_side, &buy_total, &circuit);
    let not_whole = |fills: &[Fill]| fills.iter().any(|f| !matches!(f, Fill::Whole(_)));
    let (larger, note) = match (not_whole(&buy_fills), not_whole(&sell_fills)) {
        (true, _) => ("buy", "buy side is larger"),
        (_, true) => ("sell", "sell side is larger"),
        _ => ("sell", "totals are equal, both sides fill"),
    };
    phase(
        "match",
        &format!("prefix + {} per lane, {} comparisons", circuit.describe(), engine.comparisons),
        &mut clock,
        note,
    );

    print_side(&buy_side, &buy_fills, "sell");
    print_side(&sell_side, &sell_fills, "buy");

    let units = |fills: &[Fill]| -> u64 {
        fills.iter().map(|f| match f { Fill::Whole(q) | Fill::Partial(q) => *q, Fill::None => 0 }).sum()
    };
    let (larger_fills, smaller_fills) = if larger == "buy" { (&buy_fills, &sell_fills) } else { (&sell_fills, &buy_fills) };
    let matched = units(larger_fills);
    let smaller_total = units(smaller_fills);
    let unfilled = larger_fills.iter().filter(|f| matches!(f, Fill::None)).count();
    let boundary = larger_fills.iter().filter(|f| matches!(f, Fill::Partial(_))).count();
    let revealed = |fills: &[Fill]| fills.iter().filter(|f| !matches!(f, Fill::None)).count();
    let quantities = revealed(&buy_fills) + revealed(&sell_fills);
    let masked_decryptions = engine.decryptions - engine.comparisons;

    let report = Report {
        matched,
        smaller_total,
        comparisons: engine.comparisons,
        fills_decrypted: quantities,
        unfilled,
    };

    println!();
    println!("  {:<10}{} / {}", "matched", report.matched, report.smaller_total);
    println!(
        "  {:<10}{} bit vectors, {masked_decryptions} masked decryptions, {quantities} quantities",
        "revealed", report.comparisons
    );
    println!("  {:<10}{} decryptions, each by two of three parties, no single key held", "decrypted", engine.decryptions);
    println!(
        "  {:<10}{larger} side total, {} unfilled {}, and the size of {} boundary order",
        "withheld",
        unfilled,
        if unfilled == 1 { "quantity" } else { "quantities" },
        boundary
    );
    println!("  {:<10}{:.2} s, {} comparisons", "elapsed", started.elapsed().as_secs_f64(), report.comparisons);
    println!();

    report
}

#[cfg(test)]
mod tests {
    use super::*;

    // Time priority fills the smaller side exactly, so matched == smaller_total on every book.

    #[test]
    fn toy_book() {
        assert_eq!(
            match_book("order.json", crate::TOY_DEGREE),
            Report { matched: 21, smaller_total: 21, comparisons: 3, fills_decrypted: 10, unfilled: 2 }
        );
    }

    #[test]
    fn eth_usdc_two_lanes_per_side() {
        assert_eq!(
            match_book("books/eth-usdc.json", crate::TOY_DEGREE),
            Report { matched: 13730, smaller_total: 13730, comparisons: 5, fills_decrypted: 16, unfilled: 5 }
        );
    }

    #[test]
    fn btc_usdt_sell_side_larger() {
        assert_eq!(
            match_book("books/btc-usdt.json", crate::TOY_DEGREE),
            Report { matched: 2875, smaller_total: 2875, comparisons: 2, fills_decrypted: 7, unfilled: 2 }
        );
    }

    /// About twenty seconds on eleven threads, so not in the default run: `cargo test --release -- --ignored`.
    #[test]
    #[ignore]
    fn small_lots_at_secure_degree() {
        assert_eq!(
            match_book("books/small-lots.json", SECURE_DEGREE),
            Report { matched: 2780, smaller_total: 2780, comparisons: 2, fills_decrypted: 14, unfilled: 0 }
        );
    }

    #[test]
    fn circuit_choice_follows_the_book_range() {
        assert!(matches!(Circuit::for_range(2781), Circuit::Ranged(t) if t.range == 4096));
        assert!(matches!(Circuit::for_range(4097), Circuit::Ranged(t) if t.range == 16384));
        assert!(matches!(Circuit::for_range(19716), Circuit::Full));
    }

    /// Totals below 4096, so the shipped 4096 table is used.
    #[test]
    fn small_lots_use_the_ranged_circuit() {
        assert_eq!(
            match_book("books/small-lots.json", crate::TOY_DEGREE),
            Report { matched: 2780, smaller_total: 2780, comparisons: 4, fills_decrypted: 14, unfilled: 0 }
        );
    }

    #[test]
    fn equal_remainder_fills_exactly_then_partial_of_zero() {
        assert_eq!(
            match_book("books/equal-remainder.json", crate::TOY_DEGREE),
            Report { matched: 500, smaller_total: 500, comparisons: 2, fills_decrypted: 4, unfilled: 1 }
        );
    }
}
