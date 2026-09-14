use bfv::{Ciphertext, Encoding, Evaluator, SecretKey};
use byteorder::{ByteOrder, LittleEndian};
use std::{
    io::Write,
    path::{Path, PathBuf},
};

pub fn store_values(values: &[u64], file_name: &str) {
    let mut buf = vec![0u8; values.len() * 8];
    LittleEndian::write_u64_into(values, &mut buf);
    println!("Writing into buffer done!!");

    let output_dir = Path::new("./data");
    std::fs::create_dir_all(output_dir).expect("Create ./data failed");
    
    let mut file_path = PathBuf::from(output_dir);
    file_path.push(file_name);
    
    println!("Writing into file: {:?}", file_path);
    let mut f = std::fs::File::create(file_path).unwrap();
    f.write_all(&buf).unwrap();
    println!("Writing into file done!!");
}

/// Debug helper for tests and experiments. Deliberately not used by any operator.
pub fn decrypt_and_print(evaluator: &Evaluator, ct: &Ciphertext, sk: &SecretKey, tag: &str) {
    let m = evaluator.plaintext_decode(&evaluator.decrypt(sk, ct), Encoding::default());
    println!("{tag} m: {:?}", m);
}

pub fn convert_u64_to_i64(values: &[u64], modq: u64) -> Vec<i64> {
    let q_by_2 = modq / 2;

    values
        .iter()
        .map(|v| {
            if *v < q_by_2 {
                *v as i64
            } else {
                -((modq - *v) as i64)
            }
        })
        .collect()
}
