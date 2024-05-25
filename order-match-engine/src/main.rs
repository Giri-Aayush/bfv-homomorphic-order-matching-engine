use bfv::*;
use operators::*;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;

#[derive(Serialize, Deserialize, Debug)]
struct Orders {
    pair: String,
    buy_orders: Vec<u64>,
    sell_orders: Vec<u64>,
}

fn main() {
    println!("================================================");
    println!("         Order Matching Process");
    println!("================================================");

    // plaintext modulus
    let t = 65537;

    // no of slots
    let slots = 1 << 4;

    println!("Initializing parameters:");
    println!("- Plaintext modulus: {}", t);
    println!("- Number of slots: {}", slots);
    println!("------------------------------------------------");

    let mut rng = thread_rng();

    let mut params = BfvParameters::new(&[60; 10], t, slots);

    // P - 180 bits
    params.enable_hybrid_key_switching(&[60; 3]);

    println!("Generating secret key...");
    let sk = SecretKey::random_with_params(&params, &mut rng);
    println!("Secret key generated.");
    println!("------------------------------------------------");

    println!("Creating evaluator...");
    let evaluator = Evaluator::new(params);
    println!("Evaluator created.");
    println!("------------------------------------------------");

    println!("Generating evaluation key...");
    let ek = EvaluationKey::new(evaluator.params(), &sk, &[0], &[0], &[1], &mut rng);
    println!("Evaluation key generated.");
    println!("------------------------------------------------");

    println!("Opening and reading the order file...");
    let file_path = "order.json";
    let mut file = File::open(file_path).expect("File not found");

    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("Failed to read file");
    println!("Order file read successfully.");
    println!("------------------------------------------------");

    println!("Parsing JSON data...");
    let order_data: Orders = serde_json::from_str(&contents).expect("Failed to parse JSON");
    println!("JSON data parsed.");
    println!("------------------------------------------------");

    println!("Extracting buy and sell orders...");
    let buy_orders_plain = order_data.buy_orders;
    let sell_orders_plain = order_data.sell_orders;
    println!("Buy orders (plain): {:?}", buy_orders_plain);
    println!("Sell orders (plain): {:?}", sell_orders_plain);
    println!("------------------------------------------------");

    let order_len = buy_orders_plain.len();

    println!("Formatting buy orders for encoding...");
    let buy_orders_formatted_plain = buy_orders_plain
        .iter()
        .map(|x| {
            let mut val = vec![0; slots];
            val[0] = *x;
            val
        })
        .collect::<Vec<Vec<u64>>>();
    println!("Buy orders formatted for encoding.");
    println!("------------------------------------------------");

    println!("Formatting sell orders for encoding...");
    let sell_orders_formatted_plain = sell_orders_plain
        .iter()
        .map(|x| {
            let mut val = vec![0; slots];
            val[0] = *x;
            val
        })
        .collect::<Vec<Vec<u64>>>();
    println!("Sell orders formatted for encoding.");
    println!("------------------------------------------------");

    println!("Encoding buy orders...");
    let encoded_buy_orders: Vec<Plaintext> = buy_orders_formatted_plain
        .iter()
        .map(|x| evaluator.plaintext_encode(&x, Encoding::default()))
        .collect::<Vec<Plaintext>>();
    println!("Buy orders encoded.");
    println!("------------------------------------------------");

    println!("Encoding sell orders...");
    let encoded_sell_orders: Vec<Plaintext> = sell_orders_formatted_plain
        .iter()
        .map(|x| evaluator.plaintext_encode(&x, Encoding::default()))
        .collect::<Vec<Plaintext>>();
    println!("Sell orders encoded.");
    println!("------------------------------------------------");

    println!("Encrypting buy orders...");
    let encrypted_buy_orders: Vec<Ciphertext> = encoded_buy_orders
        .iter()
        .map(|x| evaluator.encrypt(&sk, &x, &mut rng))
        .collect::<Vec<Ciphertext>>();
    println!("Buy orders encrypted.");
    println!("------------------------------------------------");

    println!("Encrypting sell orders...");
    let encrypted_sell_orders: Vec<Ciphertext> = encoded_sell_orders
        .iter()
        .map(|x| evaluator.encrypt(&sk, &x, &mut rng))
        .collect::<Vec<Ciphertext>>();
    println!("Sell orders encrypted.");
    println!("------------------------------------------------");

    println!("Summing up buy order values (encrypted)...");
    let sum_buy_orders = encrypted_buy_orders
        .iter()
        .skip(1)
        .fold(encrypted_buy_orders[0].clone(), |acc, x| {
            evaluator.add(&acc, &x)
        });
    println!("Sum of buy orders (encrypted): {:?}", sum_buy_orders);
    println!("------------------------------------------------");

    println!("Summing up sell order values (encrypted)...");
    let sum_sell_orders = encrypted_sell_orders
        .iter()
        .skip(1)
        .fold(encrypted_sell_orders[0].clone(), |acc, x| {
            evaluator.add(&acc, &x)
        });
    println!("Sum of sell orders (encrypted): {:?}", sum_sell_orders);
    println!("------------------------------------------------");

    println!("Comparing sum of buy orders and sell orders (encrypted)...");
    let is_buy_sum_less_encrypted =
        univariate_less_than(&evaluator, &sum_buy_orders, &sum_sell_orders, &ek, &sk);
    println!("Comparison result (encrypted): {:?}", is_buy_sum_less_encrypted);
    println!("------------------------------------------------");

    println!("Decrypting the comparison result...");
    let is_buy_sum_less_plain = evaluator.plaintext_decode(
        &evaluator.decrypt(&sk, &is_buy_sum_less_encrypted),
        Encoding::default(),
    );
    println!("Comparison result (decrypted): {:?}", is_buy_sum_less_plain);
    println!("------------------------------------------------");

    let transaction_volume;
    let addressable_transaction_volume;

    let mut buy_orders_filled_plain = vec![0; buy_orders_plain.len()];
    let mut sell_orders_filled_plain = vec![0; sell_orders_plain.len()];

    match is_buy_sum_less_plain[0] {
        0 => {
            println!("Sum of buy orders is greater than or equal to sum of sell orders.");
            let sum_buy_orders_plain = evaluator.plaintext_decode(
                &evaluator.decrypt(&sk, &sum_buy_orders),
                Encoding::default(),
            );
            let sum_sell_orders_plain = evaluator.plaintext_decode(
                &evaluator.decrypt(&sk, &sum_sell_orders),
                Encoding::default(),
            );
            transaction_volume = sum_buy_orders_plain[0];
            addressable_transaction_volume = sum_sell_orders_plain[0];
            println!("Transaction Volume: {}", transaction_volume);
            println!("Addressable Transaction Volume: {}", addressable_transaction_volume);

            println!("Filling buy orders using sell order sum...");

            let mut remaining_sell_orders_sum = sum_sell_orders.clone();

            for (index, order) in encrypted_buy_orders.iter().enumerate() {
                let is_less_encrypted =
                    univariate_less_than(&evaluator, order, &remaining_sell_orders_sum, &ek, &sk);
                let is_less_plain = evaluator.plaintext_decode(
                    &evaluator.decrypt(&sk, &is_less_encrypted),
                    Encoding::default(),
                );

                match is_less_plain[0] {
                    0 => {
                        println!("Cannot fill Buy Order #{}", index + 1);
                        buy_orders_filled_plain[index] = 0;
                    }
                    1 => {
                        println!("Filling Buy Order #{}", index + 1);
                        remaining_sell_orders_sum =
                            evaluator.sub(&remaining_sell_orders_sum, order);
                        buy_orders_filled_plain[index] = buy_orders_plain[index];
                    }
                    _ => println!("This condition is not possible!!"),
                }
            }

            sell_orders_filled_plain = sell_orders_plain.clone();
        }
        1 => {
            println!("Sum of buy orders is less than sum of sell orders.");
            let sum_buy_orders_plain = evaluator.plaintext_decode(
                &evaluator.decrypt(&sk, &sum_buy_orders),
                Encoding::default(),
            );
            let sum_sell_orders_plain = evaluator.plaintext_decode(
                &evaluator.decrypt(&sk, &sum_sell_orders),
                Encoding::default(),
            );
            transaction_volume = sum_sell_orders_plain[0];
            addressable_transaction_volume = sum_buy_orders_plain[0];
            println!("Transaction Volume: {}", transaction_volume);
            println!("Addressable Transaction Volume: {}", addressable_transaction_volume);

            println!("Filling sell orders using buy order sum...");

            let mut remaining_buy_orders_sum = sum_buy_orders.clone();

            for (index, order) in encrypted_sell_orders.iter().enumerate() {
                let is_less_encrypted =
                    univariate_less_than(&evaluator, order, &remaining_buy_orders_sum, &ek, &sk);
                let is_less_plain = evaluator.plaintext_decode(
                    &evaluator.decrypt(&sk, &is_less_encrypted),
                    Encoding::default(),
                );

                match is_less_plain[0] {
                    0 => {
                        println!("Cannot fill Sell Order #{}", index + 1);
                        sell_orders_filled_plain[index] = 0;
                    }
                    1 => {
                        println!("Filling Sell Order #{}", index + 1);
                        remaining_buy_orders_sum = evaluator.sub(&remaining_buy_orders_sum, order);
                        sell_orders_filled_plain[index] = sell_orders_plain[index];
                    }
                    _ => println!("This condition is not possible!!"),
                }
            }

            buy_orders_filled_plain = buy_orders_plain.clone();
        }
        _ => println!("This condition is not possible!!"),
    }

    println!("Decrypting and decoding buy orders...");
    println!("Buy orders (decrypted):");
    for (index, &order) in buy_orders_filled_plain.iter().enumerate() {
        println!("Buy Order #{}: {}", index + 1, order);
    }
    println!("------------------------------------------------");

    println!("Decrypting and decoding sell orders...");
    println!("Sell orders (decrypted):");
    for (index, &order) in sell_orders_filled_plain.iter().enumerate() {
        println!("Sell Order #{}: {}", index + 1, order);
    }
    println!("------------------------------------------------");

    println!("Order matching process completed.");
}