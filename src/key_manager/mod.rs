use std::fs;
mod wallet_meta;

use bip39::{Language, Mnemonic, Seed};
use ethnum::U256;
use libsecp256k1::{PublicKey, SecretKey};
use rocksdb::DB as RocksDB;
use serde_json::Value;
use tiny_hderive::bip32::ExtendedPrivKey;

use crate::kdf::{Crypto, EncPair, KdfParams, Key, Pbkdf2Params, SCryptParams};
use crate::error::{Error, Result};
use crate::key_manager::wallet_meta::WalletMeta;

pub struct KeyManager {
    db: RocksDB, // (address, WalletMeta)
}

pub struct KeyPair {
    pub private_key: String,
    pub public_key:  String,
}

impl KeyManager {
    pub fn new(dir: &str, db_path: &str) -> Self {
        let db = RocksDB::open_default(db_path).unwrap();
        let paths = fs::read_dir(dir).unwrap();

        for path in paths {
            let path = path.unwrap().path();
            if path.is_dir() {
                panic!("Shold be file: {}", path.to_str().unwrap());
            }
            let data = fs::read_to_string(path).unwrap();
            let json: Value = serde_json::from_str(&data).unwrap();
            let kdf = json["crypto"]["kdf"].as_str().unwrap();
            let meta = WalletMeta::from_json(kdf, &data).unwrap();

            let encoded: Vec<u8> = bincode::serialize(&meta).unwrap();
            db.put(meta.address(), encoded).unwrap();
        }

        Self { db }
    }

    pub fn find_key(&self, address: &str, password: &str) -> Result<KeyPair> {
        let wallet_meta = &self
            .get_wallet_metadata(address)
            .ok_or(Error::WalletMetaNotFound(address.to_owned()))?;

        if wallet_meta.version() == 44 {
            let mnemonic = match wallet_meta {
                WalletMeta::Pbkdf2WalletMeta(w) => {
                    decrypt_enc_pair::<Pbkdf2Params>(&w.crypto, password, &w.enc_mnemonic)
                }
                WalletMeta::ScryptWalletMeta(w) => {
                    decrypt_enc_pair::<SCryptParams>(&w.crypto, password, &w.enc_mnemonic)
                }
            };
            let path = format!("{}{}", wallet_meta.mnemonic_path(), "/0/0");
            let key_pair = derive_key_pair_from_mnemonic(&mnemonic, &path);
            Ok(KeyPair {
                private_key: format!("{}{}", "0x", key_pair.0),
                public_key:  format!("{}{}", "0x", key_pair.1),
            })
        } else {
            let private_key = match wallet_meta {
                WalletMeta::Pbkdf2WalletMeta(w) => {
                    decrypt_ciphertext::<Pbkdf2Params>(&w.crypto, password)
                }
                WalletMeta::ScryptWalletMeta(w) => {
                    decrypt_ciphertext::<SCryptParams>(&w.crypto, password)
                }
            };
            Ok(KeyPair {
                private_key: format!("{}{}", "0x", private_key),
                public_key:  format!("{}{}", "0x", gen_pub_key(&private_key)),
            })
        }
    }

    fn get_wallet_metadata(&self, address: &str) -> Option<WalletMeta> {
        if let Some(value) = self
            .db
            .get(address)
            .expect("Failed to read RocksDB")
            .as_ref()
        {
            let decoded: WalletMeta = bincode::deserialize(&value[..]).unwrap();
            return Some(decoded);
        }
        None
    }
}

fn decrypt_ciphertext<T: KdfParams>(crypto: &Crypto<T>, password: &str) -> String {
    let decrypted = crypto.decrypt(Key::Password(password.to_owned())).unwrap();
    hex::encode(decrypted)
}

fn decrypt_enc_pair<T: KdfParams>(
    crypto: &Crypto<T>,
    password: &str,
    enc_pair: &EncPair,
) -> String {
    let decrypted_bytes = crypto
        .decrypt_enc_pair(Key::Password(password.to_owned()), enc_pair)
        .unwrap();
    String::from_utf8(decrypted_bytes).unwrap()
}

fn derive_key_pair_from_mnemonic(mnemonic: &str, path: &str) -> (String, String) {
    let mnemonic = Mnemonic::from_phrase(mnemonic, Language::English).unwrap();
    let seed = Seed::new(&mnemonic, "");

    let account = ExtendedPrivKey::derive(seed.as_bytes(), path).unwrap();

    let secret_key = SecretKey::parse(&account.secret()).unwrap();
    let public_key = PublicKey::from_secret_key(&secret_key);

    (
        hex::encode(account.secret()),
        hex::encode(public_key.serialize()),
    )
}

fn gen_pub_key(privkey: &str) -> String {
    let privkey_hex = if privkey.starts_with("0x") {
        privkey.to_owned()
    } else {
        format!("0x{}", privkey)
    };
    // little endian?
    let secret_key =
        SecretKey::parse_slice(&U256::from_str_hex(&privkey_hex).unwrap().to_le_bytes()).unwrap();
    let public_key = PublicKey::from_secret_key(&secret_key);
    hex::encode(public_key.serialize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_key_test() {
        let password = "Insecure Pa55w0rd";
        let dir = "./src/key_manager/keystore";
        let db_path = "./rocksdb";

        let key_manager = KeyManager::new(dir, db_path);

        let key_pair = key_manager
            .find_key("6031564e7b2f5cc33737807b2e58daff870b590b", password)
            .unwrap();
        assert_eq!(
            "0xcce64585e3b15a0e4ee601a467e050c9504a0db69a559d7ec416fa25ad3410c2".to_owned(),
            key_pair.private_key
        );

        let key_pair = key_manager
            .find_key("12z6UzsA3tjpaeuvA2Zr9jwx19Azz74D6g", password)
            .unwrap();
        assert_eq!(
            "0x1cce15938a41062c2875b62deae13758128314c0ec5ee55180c55a2ee515d659".to_owned(),
            key_pair.private_key
        );
    }
}
