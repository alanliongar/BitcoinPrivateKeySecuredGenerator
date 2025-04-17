use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Sha256, Digest};
use ripemd160::Ripemd160;
use bs58;
use hex;

use k256::ecdsa::SigningKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::EncodedPoint;

fn main() {
    let mut rng = OsRng;
    let mut key_bytes = [0u8; 32];
    rng.fill_bytes(&mut key_bytes);

    let secret_key = SigningKey::from_bytes(&key_bytes.into()).expect("Erro ao criar chave privada");

    let public_key = secret_key.verifying_key();
    let uncompressed_pubkey: EncodedPoint = public_key.to_encoded_point(false); // chave pública NÃO comprimida

    let sha256 = Sha256::digest(uncompressed_pubkey.as_bytes());
    let ripemd = Ripemd160::digest(&sha256);

    let mut prefixed = vec![0x00];
    prefixed.extend_from_slice(&ripemd);

    let checksum = Sha256::digest(&Sha256::digest(&prefixed));
    let address_bytes = [&prefixed[..], &checksum[..4]].concat();

    let address = bs58::encode(address_bytes).into_string();

    println!("Chave privada (64 hex): {}", hex::encode(&key_bytes));
    println!("Endereço Bitcoin (uncompressed): {}", address);
}
