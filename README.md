# BFV Homomorphic Order Matching Engine

[![ci](https://github.com/Giri-Aayush/bfv-homomorphic-order-matching-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/Giri-Aayush/bfv-homomorphic-order-matching-engine/actions/workflows/ci.yml)

Exchanges that see order flow can exploit it: front-running, information leakage from dark pool operators, and MEV extraction all stem from a matching engine that reads orders in the clear. This project explores the alternative, a matching engine written in Rust that performs its arithmetic (order aggregation, running volume, less-than comparisons) on BFV-encrypted order quantities, so the arithmetic of matching never touches a plaintext quantity.

One caveat up front, stated precisely in [What is encrypted and what is revealed](#what-is-encrypted-and-what-is-revealed): comparison results are decrypted at each decision point to drive control flow, so the process is not zero-knowledge end to end. Decryption needs two of three key shares and no process holds a secret key after setup, but the three roles run in one binary with a trusted dealer, not on separate machines. The homomorphic circuits themselves (sums, subtraction, comparison polynomials) are real and tested.

## Quickstart

```sh
git clone https://github.com/Giri-Aayush/bfv-homomorphic-order-matching-engine.git
cd bfv-homomorphic-order-matching-engine/order-match-engine
cargo run --release
```

Requires a Rust toolchain with edition 2024 support (Rust 1.85 or later). With no argument the engine reads `order-match-engine/order.json`, the toy book used throughout this README:

```json
{
  "pair": "USDC/USDT",
  "buy_orders": [6, 6, 6, 6, 6, 6],
  "sell_orders": [1, 2, 3, 4, 5, 6]
}
```

Pass a path to run a different book. Orders can be bare quantities or `{"id": "...", "qty": N}` objects. Ids are not secret and appear in the report. Quantities are what gets encrypted.

```sh
cargo run --release -- books/eth-usdc.json             # the sequential walk, one comparison per order
cargo run --release -- --packed books/eth-usdc.json    # packed, one comparison per lane of orders
cargo run --release -- --secure books/small-lots.json  # packed at n = 2^15, about 16 s and 2.2 GB
```

The two matchers are described below and print the same shape of report, so a book can be run both ways and compared line by line. `--secure` is the packed matcher at a real ring degree, and it refuses a book whose range has no shipped comparison table, since the full circuit does not fit the noise budget at that degree.

### Sample books

| Book | What it exercises | Walk | Packed |
| --- | --- | --- | --- |
| `order.json` | The toy book: 36 against 21. | 7 comparisons, 18 of 21 | 3 comparisons, 21 of 21 |
| `books/eth-usdc.json` | Eleven buys with ids against ten sells, three lanes per side at the toy degree. | 12 comparisons, 13,715 of 13,730 | 5 comparisons, 13,730 of 13,730 |
| `books/btc-usdt.json` | The sell side is larger. | 6 comparisons, 2,540 of 2,875 | 2 comparisons, 2,875 of 2,875 |
| `books/equal-remainder.json` | An order exactly equals what is left at its turn. | The walk's strict less-than leaves it unfilled | Fills exactly, then a partial of zero |
| `books/small-lots.json` | Eight buys against six sells with both totals below 4,096, so the packed matcher uses the shipped 4,096 comparison table. Also the `--secure` demo. | 9 comparisons, 2,645 of 2,780, 0.16 s | 4 comparisons, 2,780 of 2,780, 0.04 s |

The engine refuses a book whose side total reaches t/2 = 32768, since the comparison circuit is only correct below that bound. It also refuses an empty side, a zero quantity, and a duplicate id. All of these are the submitter's checks, done on plaintext the submitter already holds, before anything is encrypted.

### Tests

```sh
(cd caird/operators && cargo test --release)     # the comparison circuit
(cd order-match-engine && cargo test --release)  # every shipped book, results pinned
```

The operators crate has fourteen tests and the engine eleven plus one ignored: a random-vector comparison across all 16 slots, a sixteen-edge-case comparison (equal operands, zero against one, the largest legal operand against zero and against itself, neighbours one apart) that also pins the noise left after the circuit, the packed primitives (mask, prefix sum, broadcast total) each checked against plaintext with a final test that runs prefix, broadcast and comparison together and pins that noise too, the ranged comparison: its tables checked at every interpolation point, both evaluators checked exhaustively on all 576 pairs below 24, agreement with the full circuit on random inputs below 4,096, and the shipped tables loaded and exercised. And the roles: public-key ciphertexts decrypt under the secret and cost only a few bits more, a comparison on them fits the budget, all four orderings of party pairs reconstruct a reference decryption, and one party alone does not. The engine crate runs every book in both modes and pins five numbers for each: units matched, the smaller side's total, comparisons made, quantities decrypted, orders left unfilled. A change to the circuit, either matcher, or the decryption accounting shows up as a diff in one of those. The ignored test is the small-lots book at n = 2^15, about 16 s on eleven threads: `cargo test --release -- --ignored`. CI runs all of it on every push, the secure run included.

## What the engine does

The matching model is volume crossing on quantities, not a price-time-priority limit order book:

1. Each buy and sell quantity is encoded into slot 0 of its own BFV plaintext and encrypted. The plaintext inputs are dropped at that point.
2. The engine homomorphically sums all buy ciphertexts and all sell ciphertexts. Neither total is decrypted as a ciphertext.
3. A homomorphic less-than compares the two encrypted sums. The single result bit is decrypted to learn which side has more volume.
4. The engine walks the larger side's orders in input sequence. For each order it homomorphically compares the encrypted order against the encrypted remaining volume of the smaller side and decrypts the result bit. If the order is strictly less than the remainder, it is homomorphically subtracted from the remainder and its quantity is decrypted for the fill report. An unfilled order's quantity is never decrypted.
5. The smaller side is filled entirely, and its quantities are decrypted for the report.

With the sample `order.json` (buy sum 36, sell sum 21), the run fills buy orders 1 through 3 (18 units). Orders 4 to 6 are each 6 against a remainder of 3 and stay unfilled. The strict less-than also means an order exactly equal to the remainder would not fill, and partial fills are not supported.

### Packed matching (`--packed`)

The walk spends one comparison and one decrypted bit per order. The packed matcher spends one comparison per lane of orders and decrypts one bit vector for it.

1. Each side is packed into lanes of n/4 quantities per ciphertext, one per slot: four at the toy degree, 8,192 at n = 2^15. This library's rotations act within a row of n/2 slots and it has no row swap, so a lane lives in one row, and it uses only the first half of that row so that a rotation by less than a lane wraps zeros in from the empty half. The second row rides along unused.
2. Each side's total is broadcast to every slot by log2(n/2) rotate-and-adds, and stays encrypted.
3. For each lane, cumulative volume is a prefix sum by log2(n/4) rotate-and-adds with no masks, plus the total of the lanes before it. Rotations add key-switching noise only. An earlier version masked each step with a 0/1 vector, and a step mask is not a constant, so each one multiplied the noise by about t·√n. That was invisible at n = 16 and ate the whole budget at n = 2^15. One comparison of the other side's total against the prefix then gives, for every order in the lane, whether the cumulative volume through it already exceeds what the other side has. That bit vector is decrypted, and any value in it that is not a legal output stops the run, since it means the noise budget was exceeded.
4. Orders before the first set bit fill whole. Their quantities are revealed through a plaintext mask, so the decryption shows nothing else. The first set bit is the boundary order: it fills with what is left, computed as total minus prefix plus its own quantity, masked to that one slot and decrypted. Its full size is never revealed. Orders after it, and every later lane, are not computed or decrypted at all.
5. The other side is processed the same way. If it is the smaller side, no bit is ever set and it fills whole.

That is time priority with partial fills. The smaller side is filled to the unit on every book, and the equal-remainder case that the walk leaves unfilled fills exactly. It also leaks less than the walk: the bit vector says where the boundary is and nothing more, the boundary order's size stays encrypted, and nothing about orders behind it is learned, not even a lower bound. On `books/eth-usdc.json` that is 5 comparisons and 16 revealed quantities against the walk's 12 and 18.

### A comparison sized to the book (`compare_ranged`)

The full circuit's polynomial has degree t − 1 because it extracts sign over all of Z_t. But the engine knows, on the submitter's side and before anything is encrypted, that every comparison operand is below R = 1 + the larger side total. The sign function then only has to be right on 2R − 1 points, so the same odd/even split works with two polynomials in z² of degree about R, interpolated once per R:

    LT(x, y) = (1 − e(z²) − z·h(z²)) / 2,   e(0) = 1, e(k²) = 0, h(k²) = 1/k for 0 < k < R

`less_than_ranged` evaluates both and returns a bit. That costs 2R plaintext multiplies against the full circuit's 32,768, so it only wins below R ≈ t/4. `compare_ranged` evaluates only h and returns 1, 0, or t/2 + 1 for less, greater, or equal. The engine decrypts every comparison anyway, so that is all it needs, at R plaintext multiplies, and it never loses. Measured at n = 16 against the full circuit's 0.061 s: the bit form takes 0.006 s at R = 1,024, 0.017 s at 4,096 and 0.032 s at 8,192, and the three-valued form takes 0.010 s at 4,096. Noise is lower too, 290 bits against 370 at R = 4,096, because the ladders are shorter.

Tables for R = 4,096 and 16,384 ship in `order-match-engine/data/`, built once by `operators ranged <R>` (O(R²), seconds). The packed matcher picks the smallest shipped table that covers the book and falls back to the full circuit otherwise. `books/eth-usdc.json` has a buy side of 19,715 and stays on the full circuit; `books/small-lots.json` fits the 4,096 table and its whole packed run takes 0.04 s.

This corrects an earlier plan. The digit-decomposition trick in Iliashenko and Zucca compares numbers encrypted as digits. Our operands are prefix sums, which are Z_t elements produced homomorphically, and extracting digits from one of those is itself a degree-t problem. Sizing the circuit to the range is what actually composes with homomorphic summation. The trade a venue can make is coarser lots for cheaper comparisons.

### Secure parameters (`--secure`)

`--secure` runs the packed matcher at n = 2^15, the largest degree batching allows at t = 65537. With log2(QP) = 780 and a ternary secret of Hamming weight n/2, this is roughly 128-bit: the HE standard's 128-bit column for n = 32768 allows log2 q up to 881 for a uniform ternary secret, and a weight-n/2 secret is a little sparser than uniform, so treat it as roughly rather than certified.

What was measured at that degree, on eleven threads:

- The full-domain circuit takes 148 s and decrypts wrong: 583 bits of noise in a modulus of about 600. It does not fit. The ranged circuit at R = 4,096 is correct in 6.3 s with 470 bits, so at secure parameters the range-sized circuit is not only faster, it is the one that works.
- The whole `books/small-lots.json` run: 16 s, 2.2 GB peak, 2780 of 2780 matched with the boundary order partial at 135, pinned by the ignored test.
- Parallelism: the giant-step blocks were independent up to the final sum and now run on rayon, and the power ladders are built by doubling so each level's multiplications run in parallel at the same depth. Single-threaded the ranged comparison took 26 s at n = 2^15. At the toy degree the same change takes the ETH/USDC walk from 0.75 s to 0.22 s.

What is not done: modulus switching. Dropping primes as depth is consumed would make the later ladder levels and the block products cheaper, perhaps 20 to 30 percent of the comparison. It also means a level on every ciphertext and relinearization keys per level, which touches every call site. Not worth that at this stage, and the number to beat is written down here so the next person can decide.

## Architecture

Three crates, wired together by path dependencies:

| Crate | Path | Role |
| --- | --- | --- |
| `order-match-engine` | `order-match-engine/` | Binary. Loads a book, runs the matching flow above, counts what it decrypts. |
| `operators` | `caird/operators/` | Homomorphic comparison: `univariate_less_than`, `powers_of_x`, an encrypted `sort`, the coefficient precomputation `compute_lt_coefficients`, and the `packed` module (mask, prefix sum, broadcast total by rotation). |
| `bfv` | `bfv/bfv/` | The BFV scheme itself: RNS polynomial arithmetic, NTT (via `concrete-ntt`, optional Intel HEXL), encryption, relinearization, hybrid key switching. Vendored from Janmajaya Mall's `bfv` library (MIT license in `bfv/LICENSE`). |

```mermaid
flowchart TD
    subgraph P1["Plaintext (input)"]
        A[order.json] --> B[Parse buy and sell quantities]
    end

    B --> C["Encode each quantity into slot 0<br/>and encrypt under the secret key"]

    subgraph E["Encrypted domain (BFV)"]
        C --> D1["Homomorphic sum of buy orders"]
        C --> D2["Homomorphic sum of sell orders"]
        D1 --> F["univariate_less_than(buy sum, sell sum)"]
        D2 --> F
        G["univariate_less_than(order, remaining)"]
        H["Homomorphic subtract:<br/>remaining -= order"]
    end

    F -->|"decrypt 1 bit"| I{"Which side<br/>is larger?"}
    I --> K["For each order on the larger side"]
    K --> G
    G -->|"decrypt 1 bit"| L{"order < remaining?"}
    L -->|yes| H
    H -->|"decrypt quantity"| M["Report filled"]
    L -->|no| N["Report unfilled, quantity stays encrypted"]
    M --> K
    N --> K
    K -->|"decrypt smaller side"| O["Print fill report"]
```

Every decision the engine makes crosses the boundary out of the encrypted domain through a decryption of a single comparison bit. The quantities being compared and subtracted stay encrypted, and the only quantities ever decrypted are the ones that filled.

## How the cryptography works

**Library.** A vendored fork of [`Janmajayamall/bfv`](https://github.com/Janmajayamall/bfv), a from-scratch Rust implementation of the BFV scheme (Brakerski, Fan, Vercauteren) with RNS arithmetic, batching (SIMD slots), relinearization, Galois rotations, and hybrid key switching. It is not SEAL, OpenFHE, or `tfhe-rs`.

**Parameters** (set in `order-match-engine/src/main.rs`):

- Plaintext modulus t = 65537, a Fermat prime, so plaintext slots form Z_65537 and Fermat's little theorem applies with exponent 65536.
- Ring degree n = 16, so 16 SIMD slots. This is a toy dimension, see Limitations.
- Ciphertext modulus Q: ten 60-bit primes, about 600 bits total, plus a 180-bit extension modulus P for hybrid key switching.
- The library is symmetric-key only. The public key submitters encrypt under, and the 2-of-3 split decryptors hold, are built in `operators::roles` from the ring operations the library exposes. See [Three roles](#three-roles-operatorsroles).

**What runs homomorphically:**

- Additions and subtractions of ciphertexts (order sums, the running remainder).
- The less-than comparison, `univariate_less_than` in `caird/operators/src/lib.rs`. It computes z = x minus y, then evaluates the univariate sign-extraction polynomial over Z_t: the result is (t+1)/2 times z^(t-1) plus z times g(z^2), where g has degree (t-3)/2 and coefficients alpha_i equal to the sum of a^(t-1-i) for a from 1 to (t-1)/2. This is the univariate comparison construction of Iliashenko and Zucca ("Faster homomorphic comparison operations for BFV and TFHE"). The output ciphertext holds 1 in each slot where x < y and 0 otherwise, correct for inputs below t/2.
- The 32768 polynomial coefficients are precomputed by `compute_lt_coefficients`, shipped as `order-match-engine/data/less_than.bin` (262144 bytes of little-endian u64), and embedded into the operators crate at build time with `include_bytes!`, so there is no data directory to find at run time.
- Evaluation uses a baby-step giant-step split: powers z^2 through (z^2)^181 and ((z^2)^181)^1 through ((z^2)^181)^181, computed with a binary-exponentiation power ladder (`powers_of_x`) plus relinearization, then 182 blocks of 181 plaintext-multiply-and-accumulate steps.
- `operators` also contains an encrypted `sort` that builds a Hamming-weight matrix from pairwise comparisons and extracts ranked elements with an equality-test polynomial. The matching engine does not call it, and its test is commented out.

**What is decrypted, and when.** Two kinds of values leave the encrypted domain during a run, and the binary counts both:

1. One comparison bit per decision: first buy-sum versus sell-sum, then one per order on the larger side. Each is decrypted immediately so plaintext control flow can branch on it.
2. The quantity of every order that filled, for the report. On the sample book that is seven bits and nine quantities. Neither side total is decrypted as a ciphertext, though the smaller side's total is the sum of its decrypted fills. An unfilled order's quantity is never decrypted.

**Who holds what.** The comparison and packing operators take only the evaluation key. Nothing in them can decrypt. The engine holds a public key, an evaluation key and three shares, and a secret key exists only inside the dealer function during setup and in the unit tests. Every decryption is a partial from two of the three shares, combined.

## What is encrypted and what is revealed

An honest scorecard for the "zero plaintext" framing:

| Value | Encrypted during matching? | Revealed? |
| --- | --- | --- |
| Individual order quantities | Yes, all arithmetic on them is homomorphic | Filled quantities are decrypted for the report. An unfilled quantity is never decrypted, but it is bounded below by the remainder at its turn, which follows from the decrypted fills |
| Buy-side and sell-side totals | Yes, computed homomorphically | Neither is decrypted as a ciphertext. The smaller side's total follows from its decrypted fills, the larger side's does not |
| Comparison outcomes | Computed homomorphically | Yes, every result bit is decrypted to branch |
| Running unfilled remainder | Yes, updated by homomorphic subtraction | Only indirectly, through the comparison bits |
| Which orders filled | n/a (plaintext bookkeeping) | Yes, that is the output |

So the claim that holds is narrower than "zero plaintext": the arithmetic on order quantities is fully homomorphic, but the matching decisions leak one bit per comparison, and the report reveals the quantities that filled. Who learns those is now a 2-of-3 committee rather than the matcher. What is still missing for a deployment is in the next section.

### Three roles (`operators::roles`)

Until this point one process generated the secret, encrypted every order with it, ran the match, and decrypted every result. Now there are three roles, separated by what each key can do.

- **Submitters** encrypt under a public key. The library has no public-key mode, so it is built from the ring operations it exposes: with secret s, a uniform a and a Gaussian e, publish (−(a·s + e), a). Encryption samples a ternary u and two Gaussians and sets (p0·u + e1 + Δm, p1·u + e2). Fresh noise measures 5 bits against the symmetric form's 3.
- **The matcher** holds the evaluation key and the rotation keys and can decrypt nothing.
- **Decryptors** hold a replicated 2-of-3 split of the secret: s = s0 + s1 + s2 with two parts uniform, and party i holds parts i and i+1. Any two parties together hold all three, one party holds two. Decryption is linear in s, so each of two parties multiplies c1 by the parts assigned to it, adds 2^520 of uniform smudging noise, and the combiner adds c0 and decodes. Parts go to the lower-numbered holder so the two contributions are disjoint and cover the secret, and the combiner refuses partials that were not computed for each other. The smudging hides the ciphertext's own noise from the combiner, since that noise depends on the computation's inputs, and 520 bits leaves about 50 bits of margin over the noisiest measured ciphertext and about 60 under the rounding threshold.

The secret exists only inside the dealer function, which derives the public and evaluation keys, splits it, and returns without it. The engine rotates through the three pairs so one run exercises all of them, and the report says how many decryptions happened.

What is still one process: the dealer is trusted, since it saw the secret before splitting it, and the three roles are separated by keys rather than machines. Distributed key generation would remove the dealer. Separate machines need ciphertexts on the wire, and the library's `serialize` feature depends on `prost-build`, which needs `protoc` at build time, so that is a build-environment decision before it is a code one.


## Measured performance

Measured on an Apple Silicon Mac (arm64), `--release`, at the toy ring degree n = 16:

- Toy book, walk (7 comparisons, 9 decrypted fills): about 0.14 s wall clock. Packed (3 comparisons): about 0.04 s.
- `books/eth-usdc.json`, walk (12 comparisons, 18 decrypted fills): about 0.23 s. Packed (5 comparisons on the full circuit, 16 revealed quantities): about 0.11 s. Each full comparison is roughly 16 ms on eleven threads, and the binary prints per-phase timings on every run.
- `books/small-lots.json`, walk (9 comparisons): about 0.17 s. Packed (4 comparisons on the 4,096 table): about 0.04 s. With `--secure`: about 18 s, of which threshold decryption is about 2 s.
- `less_than_works` test (one comparison on fresh ciphertexts, all 16 slots at once): about 0.11 s including key generation.

These numbers do not transfer to secure parameters. Every polynomial operation scales at least with n log n, and a secure ring degree for a 600-bit modulus is three orders of magnitude larger than 16.

## Limitations

- **The default parameters are insecure.** Ring degree 16 with a 600-bit ciphertext modulus offers no meaningful lattice security. The library's own assertion floor is `degree >= 16` and the default runs at that floor. Treat every ciphertext from a default run as toy. `--secure` runs at n = 2^15, with the caveat on the secret's weight above.
- **Not zero plaintext.** See the scorecard above: comparison bits are decrypted mid-protocol and filled quantities are decrypted for the report. The party that learns them is a 2-of-3 committee, but the committee runs inside the same binary.
- **The walk's fill pattern leaks bounds.** In the sequential walk, the comparison bits together with the decrypted fills give a lower bound on every unfilled quantity. The packed matcher does not have this: past the boundary nothing is computed, so nothing is bounded. Both modes reveal the smaller side's total, since all of its fills are printed.
- **Quantities only, no prices.** Orders are u64 quantities with an optional id. There is no price, no limit book, and no time priority beyond input order. The `pair` field is only a label.
- **The walk is greedy, strict, and whole-fill only.** In the sequential walk, orders on the larger side fill first-come against the remaining volume, the strict less-than leaves an order unfilled even when it exactly equals the remainder, and an order can only fill whole. The sample run matches 18 of 21. The packed matcher replaces this with time priority and a partial fill at the boundary, and matches 21 of 21.
- **Input domain is bounded.** Comparison correctness requires values below t/2, about 32768, and the summed side must also stay below that bound. The engine checks this on load and refuses the book otherwise. The walk uses one slot per ciphertext. The packed matcher uses n/4, half a row, because the library cannot rotate across rows and the other half of the row has to be zero for mask-free prefix sums.
- **Depth budget is spent on comparison.** One `univariate_less_than` materializes two ladders of 181 powers each, one relinearized ciphertext multiplication per power, with a critical path of about eight squarings per ladder, all against a 10-prime modulus chain with no modulus switching in the call path. Measured: a single comparison leaves about 360 bits of noise in a roughly 600-bit modulus, so a second comparison on its output would not decrypt correctly. That is the concrete reason the walk decrypts a bit between steps rather than chaining. The test `less_than_edges_and_noise_budget` pins the figure. At n = 2^15 the full circuit's noise reaches 583 bits and the result is wrong, which is why `--secure` requires a range-sized circuit.
- **No benchmarks for the engine.** The `bfv` library ships Criterion benches for its primitives. The matching pipeline prints per-phase wall-clock times but has no benches.
- **Not production software.** Single binary, keys dealt per run by a trusted dealer in-process, no distributed key generation, no serialization of ciphertexts.

## Repository layout

```
order-match-engine/   binary crate: both matchers, order.json, books/, data/ (full and ranged comparison tables)
caird/operators/      comparison and sorting circuits over BFV ciphertexts
bfv/                  vendored BFV library (workspace: bfv, traits), MIT licensed
```

## Credits

The `bfv` library and the comparison operator implementation build on work by Janmajaya Mall (`bfv/LICENSE`, MIT, 2023). The comparison polynomial follows Iliashenko and Zucca, "Faster homomorphic comparison operations for BFV and TFHE", PoPETs 2021.
