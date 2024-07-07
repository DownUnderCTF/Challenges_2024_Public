use std::io::stdin;
use aes_gcm::{
    aead::{ Aead, KeyInit},
    Aes256Gcm, Key, Nonce
};

fn main() -> Result<(), std::io::Error> {
    let result: Vec<u8> = Vec::from([$RESULT]);
    let nonce = Nonce::from_slice(&[$NONCE]);

    let key: &[u8; 32] = &[$KEY];
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
