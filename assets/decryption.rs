use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key,
};

const DECRYPTION_KEY: [u8; 32] = [{KEY}];
const DECRYPTION_NONCE: [u8; 12] = [{NONCE}];

#[inline]
pub fn decrypt_shellcode(shellcode: &[u8]) -> Vec<u8> {
    let key = Key::<Aes256Gcm>::from_slice(&DECRYPTION_KEY);
    let cipher = Aes256Gcm::new(&key);
    cipher
        .decrypt((&DECRYPTION_NONCE).into(), shellcode)
        .unwrap()
}
