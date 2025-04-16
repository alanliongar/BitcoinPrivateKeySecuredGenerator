use rand::rngs::OsRng;
use rand::RngCore;
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use sha2::{Sha256, Digest};
use ripemd160::Ripemd160;
use bs58;
use hex;

fn main() {
    let mut rng = OsRng;
    let secp = Secp256k1::new();

    // Gerar 32 bytes aleatórios
    let mut key = [0u8; 32];
    rng.fill_bytes(&mut key);

    // Criar chave privada
    let secret_key = SecretKey::from_slice(&key).expect("Erro ao gerar chave privada");

    // Derivar chave pública a partir da privada
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let pubkey_bytes = public_key.serialize(); // formato comprimido (33 bytes)

    // Hash SHA-256 da chave pública
    let sha256 = Sha256::digest(&pubkey_bytes);

    // Hash RIPEMD-160 do resultado
    let ripemd = Ripemd160::digest(&sha256);

    // Prefixo de rede (0x00 para mainnet)
    let mut prefixed = vec![0x00];
    prefixed.extend_from_slice(&ripemd);

    // Checksum = 1ºs 4 bytes do SHA256(SHA256(payload))
    let checksum = Sha256::digest(&Sha256::digest(&prefixed));
    let address_bytes = [&prefixed[..], &checksum[..4]].concat();

    // Codificar em Base58
    let address = bs58::encode(address_bytes).into_string();

    // Exibir chave privada e endereço
    println!("Chave privada (64 hex): {}", hex::encode(secret_key.secret_bytes()));
    println!("Endereço Bitcoin: {}", address);
}

//Remove-Item -Recurse -Force .\target, .\Cargo.lock
