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

}