use rand::rngs::OsRng;
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use sha2::{Sha256, Digest};
use ripemd160::Ripemd160;
use bs58;

fn main() {
    // Gerador seguro
    let mut rng = OsRng;
    let secret_key = SecretKey::new(&mut rng);
    let secp = Secp256k1::new();
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);

    // Chave pública comprimida (33 bytes)
    let pubkey_serialized = public_key.serialize();

    // Hash SHA-256 da chave pública
    let sha256 = Sha256::digest(&pubkey_serialized);

    // Hash RIPEMD-160 do SHA-256
    let ripemd = Ripemd160::digest(&sha256);

    // Adiciona prefixo de rede (0x00 para mainnet)
    let mut prefixed = vec![0x00];
    prefixed.extend(&ripemd);

    // Calcula checksum (duplo SHA-256)
    let checksum = Sha256::digest(&Sha256::digest(&prefixed));
    let address_bytes = [&prefixed[..], &checksum[0..4]].concat();

    // Codifica em Base58
    let address = bs58::encode(address_bytes).into_string();

    println!("Chave privada (64 hex): {:x}", secret_key);
    println!("Endereço Bitcoin: {}", address);
}
