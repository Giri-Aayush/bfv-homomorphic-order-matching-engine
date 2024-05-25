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


    // plaintext modulus
    let t = 65537;

    // no of slots
    let slots = 1 << 4;

    let mut rng = thread_rng();

    let mut params = BfvParameters::new(&[60; 10], t, slots);

    // P - 180 bits
    params.enable_hybrid_key_switching(&[60; 3]);


    let sk = SecretKey::random_with_params(&params, &mut rng);

    let evaluator = Evaluator::new(params);

    let ek = EvaluationKey::new(evaluator.params(), &sk, &[0], &[0], &[1], &mut rng);


    let file_path = "order.json";
    let mut file = File::open(file_path).expect("File not found");

    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("Failed to read file");

    let order_data: Orders = serde_json::from_str(&contents).expect("Failed to parse JSON");


    let buy_orders_plain = order_data.buy_orders;
    let sell_orders_plain = order_data.sell_orders;

    let order_len = buy_orders_plain.len();


    let buy_orders_formatted_plain = buy_orders_plain
        .iter()
        .map(|x| {
            let mut val = vec![0; slots];
            val[0] = *x;
            val
        })
        .collect::<Vec<Vec<u64>>>();

    let sell_orders_formatted_plain = sell_orders_plain
        .iter()
        .map(|x| {
            let mut val = vec![0; slots];
            val[0] = *x;
            val
        })
        .collect::<Vec<Vec<u64>>>();


    let encoded_buy_orders: Vec<Plaintext> = buy_orders_formatted_plain
        .iter()
        .map(|x| evaluator.plaintext_encode(&x, Encoding::default()))
        .collect::<Vec<Plaintext>>();

    let encoded_sell_orders: Vec<Plaintext> = sell_orders_formatted_plain
        .iter()
        .map(|x| evaluator.plaintext_encode(&x, Encoding::default()))
        .collect::<Vec<Plaintext>>();

    let encrypted_buy_orders: Vec<Ciphertext> = encoded_buy_orders
        .iter()
        .map(|x| evaluator.encrypt(&sk, &x, &mut rng))
        .collect::<Vec<Ciphertext>>();
    println!("Buy orders encrypted.");
    println!("Encrypted buy orders:");
    for ct in &encrypted_buy_orders {
        println!("{:?}", ct);
    }

    let encrypted_sell_orders: Vec<Ciphertext> = encoded_sell_orders
        .iter()
        .map(|x| evaluator.encrypt(&sk, &x, &mut rng))
        .collect::<Vec<Ciphertext>>();
    println!("Sell orders encrypted.");
    println!("Encrypted sell orders:");
    for ct in &encrypted_sell_orders {
        println!("{:?}", ct);
    }

    let sum_buy_orders = encrypted_buy_orders
        .iter()
        .skip(1)
        .fold(encrypted_buy_orders[0].clone(), |acc, x| {
            let sum = evaluator.add(&acc, &x);
            println!("Intermediate sum (encrypted): {:?}", sum);
            sum
        });

    let sum_sell_orders = encrypted_sell_orders
        .iter()
        .skip(1)
        .fold(encrypted_sell_orders[0].clone(), |acc, x| {
            let sum = evaluator.add(&acc, &x);
            println!("Intermediate sum (encrypted): {:?}", sum);
            sum
        });


    let is_buy_sum_less_encrypted =
        univariate_less_than(&evaluator, &sum_buy_orders, &sum_sell_orders, &ek, &sk);
    println!("Comparison result (encrypted): {:?}", is_buy_sum_less_encrypted);

    let is_buy_sum_less_plain = evaluator.plaintext_decode(
        &evaluator.decrypt(&sk, &is_buy_sum_less_encrypted),
        Encoding::default(),
    );

   
    match is_buy_sum_less_plain[0] {
        0 => {
            println!("Sum of buy orders is greater than or equal to sum of sell orders.");
            let transaction_volume = evaluator.plaintext_decode(
                &evaluator.decrypt(&sk, &sum_buy_orders),
                Encoding::default(),
            );
            println!("Transaction Volume: {:?}", transaction_volume[0]);
        }
        1 => {
            println!("Sum of buy orders is less than sum of sell orders.");
            let transaction_volume = evaluator.plaintext_decode(
                &evaluator.decrypt(&sk, &sum_sell_orders),
                Encoding::default(),
            );
            println!("Transaction Volume: {:?}", transaction_volume[0]);
        }
        _ => println!("This condition is not possible!!"),
    }
    

    let mut sum_sell_orders_temp = sum_sell_orders.clone();
    let mut sum_buy_orders_temp = sum_buy_orders.clone();

    let mut buy_orders_filling_encrypted: Vec<Ciphertext> = vec![];
    let mut sell_orders_filling_encrypted: Vec<Ciphertext> = vec![];

    println!("Filling buy orders...");
    for (index, order) in encrypted_buy_orders.iter().enumerate() {
        println!("Processing Buy Order #{}", index + 1);
        let is_less_encrypted =
            univariate_less_than(&evaluator, order, &sum_sell_orders_temp, &ek, &sk);
        println!("Is buy order less than remaining sell orders (encrypted): {:?}", is_less_encrypted);
        let is_less_plain = evaluator.plaintext_decode(
            &evaluator.decrypt(&sk, &is_less_encrypted),
            Encoding::default(),
        );

        match is_less_plain[0] {
            0 => {
                println!("Buy Order #{} cannot be filled.", index + 1);
                let zero_value_order = vec![0; slots];
                let zero_value_order_encoded = evaluator.plaintext_encode(&zero_value_order, Encoding::default());
                let zero_value_order_encrypted = evaluator.encrypt(&sk, &zero_value_order_encoded, &mut rng);
                buy_orders_filling_encrypted.push(zero_value_order_encrypted);
            }
            1 => {
                println!("Buy Order #{} filled.", index + 1);
                sum_sell_orders_temp = evaluator.sub(&sum_sell_orders_temp, order);
                println!("Remaining sell orders (encrypted): {:?}", sum_sell_orders_temp);
                buy_orders_filling_encrypted.push(order.clone());
            }
            _ => println!("This condition is not possible!!"),
        }
    }

    println!("Filling sell orders...");
    for (index, order) in encrypted_sell_orders.iter().enumerate() {
        println!("Processing Sell Order #{}", index + 1);
        let is_less_encrypted =
            univariate_less_than(&evaluator, order, &sum_buy_orders_temp, &ek, &sk);
        println!("Is sell order less than remaining buy orders (encrypted): {:?}", is_less_encrypted);
        let is_less_plain = evaluator.plaintext_decode(
            &evaluator.decrypt(&sk, &is_less_encrypted),
            Encoding::default(),
        );

        match is_less_plain[0] {
            0 => {
                println!("Sell Order #{} cannot be filled.", index + 1);
                let zero_value_order = vec![0; slots];
                let zero_value_order_encoded = evaluator.plaintext_encode(&zero_value_order, Encoding::default());
                let zero_value_order_encrypted = evaluator.encrypt(&sk, &zero_value_order_encoded, &mut rng);
                sell_orders_filling_encrypted.push(zero_value_order_encrypted);
            }
            1 => {
                println!("Sell Order #{} filled.", index + 1);
                sum_buy_orders_temp = evaluator.sub(&sum_buy_orders_temp, order);
                println!("Remaining buy orders (encrypted): {:?}", sum_buy_orders_temp);
                sell_orders_filling_encrypted.push(order.clone());
            }
            _ => println!("This condition is not possible!!"),
        }
    }

}