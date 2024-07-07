use std::io::stdin;
use aes_gcm::{
    aead::{ Aead, KeyInit},
    Aes256Gcm, Key, Nonce
};

fn main() -> Result<(), std::io::Error> {
    let result: Vec<u8> = Vec::from([250,166,86,50,195,113,48,205,41,22,22,15,57,79,231,101,46,250,5,219,204,234,71,18,200,244,127,237,144,48,246,173,171,177,80,167,162,207,181,209,59,46,179,154,254,54,160,142,144,24,159,4,231,203,121,97,92,217,91,56]);
    let nonce = Nonce::from_slice(&[255,6,114,69,198,174,123,159,193,54,212,142]);

    let key: &[u8; 32] = &[149,135,232,231,222,192,60,40,162,140,161,247,53,39,35,129,108,33,110,16,113,74,98,11,158,54,120,147,56,150,144,207];
    let key: &Key<Aes256Gcm> = key.into();
    let cipher2 = Aes256Gcm::new(&key);

    let mut plaintext = String::new();
    println!("Enter the password to unlock the vault: ");
    stdin().read_line(&mut plaintext)?;
    plaintext = plaintext.trim_end().to_string();
    let ciphertext = cipher2.encrypt(nonce, plaintext.as_bytes());
 
    if result == ciphertext.unwrap() {
        println!("Congratulations, you have opened the vault.");
    } else {
        println!("nope");
    }
    Ok(())
}
