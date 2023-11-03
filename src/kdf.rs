// Reference https://github.com/consenlabs/token-core/blob/dev/tcx-crypto/src/crypto.rs

use bitcoin_hashes::hex::{FromHex, ToHex};
use hmac;
use pbkdf2;
use rand::{thread_rng, RngCore};
use scrypt;
use serde::{Deserialize, Serialize};
use sha2::{self, Digest, Sha256};

use crate::aes;
use crate::error::{Error, Result};

const CREDENTIAL_LEN: usize = 64usize;

pub type Credential = [u8; CREDENTIAL_LEN];

pub enum Key {
    Password(String),
    DerivedKey(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Crypto<T: KdfParams> {
    cipher:             String,
    cipherparams:       CipherParams,
    ciphertext:         String,
    kdf:                String,
    kdfparams:          T,
    mac:                String,
    #[serde(skip)]
    cached_derived_key: Option<CacheDerivedKey>,
}

impl<T> Crypto<T>
where
    T: KdfParams,
{
    pub fn kdf(&self) -> &str {
        &self.kdf
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CipherParams {
    iv: String,
}

pub trait KdfParams {
    fn kdf_key() -> String;
    fn validate(&self) -> Result<()>;
    fn generate_derived_key(&self, password: &[u8], out: &mut [u8]);
    fn set_salt(&mut self, salt: &str);
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Pbkdf2Params {
    c:     u32,
    prf:   String,
    dklen: u32,
    salt:  String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SCryptParams {
    n:     u32,
    p:     u32,
    r:     u32,
    dklen: u32,
    salt:  String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncPair {
    pub enc_str: String,
    pub nonce:   String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CacheDerivedKey {
    hashed_key:  String,
    derived_key: Vec<u8>,
}

impl CacheDerivedKey {
    #[allow(dead_code)]
    pub fn new(key: &str, derived_key: &[u8]) -> CacheDerivedKey {
        CacheDerivedKey {
            hashed_key:  Self::hash(key),
            derived_key: derived_key.to_vec(),
        }
    }

    fn hash(key: &str) -> String {
        hex_dsha256(key)
    }

    pub fn get_derived_key(&self, key: &str) -> Result<Vec<u8>> {
        if self.hashed_key == Self::hash(key) {
            Ok(self.derived_key.clone())
        } else {
            Err(Error::PasswordIncorrect)
        }
    }
}

impl KdfParams for Pbkdf2Params {
    fn kdf_key() -> String {
        "pbkdf2".to_owned()
    }

    fn validate(&self) -> Result<()> {
        if self.dklen == 0 || self.c == 0 || self.salt.is_empty() || self.prf.is_empty() {
            Err(Error::KdfParamsInvalid)
        } else {
            Ok(())
        }
    }

    fn generate_derived_key(&self, password: &[u8], out: &mut [u8]) {
        let salt_bytes: Vec<u8> = FromHex::from_hex(&self.salt).unwrap();
        pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(password, &salt_bytes, self.c as usize, out);
    }

    fn set_salt(&mut self, salt: &str) {
        self.salt = salt.to_owned();
    }
}

impl KdfParams for SCryptParams {
    fn kdf_key() -> String {
        "scrypt".to_owned()
    }

    fn validate(&self) -> Result<()> {
        if self.dklen == 0 || self.n == 0 || self.salt.is_empty() || self.p == 0 || self.r == 0 {
            Err(Error::KdfParamsInvalid)
        } else {
            Ok(())
        }
    }

    fn generate_derived_key(&self, password: &[u8], out: &mut [u8]) {
        let salt_bytes: Vec<u8> = FromHex::from_hex(&self.salt).unwrap();
        let log_n = (self.n as f64).log2().round();
        let inner_params =
            scrypt::ScryptParams::new(log_n as u8, self.r, self.p).expect("init scrypt params");

        scrypt::scrypt(password, &salt_bytes, &inner_params, out).expect("can not execute scrypt");
    }

    fn set_salt(&mut self, salt: &str) {
        self.salt = salt.to_owned();
    }
}

impl<T> Crypto<T>
where
    T: KdfParams,
{
    pub fn decrypt(&self, key: Key) -> Result<Vec<u8>> {
        let encrypted: Vec<u8> = FromHex::from_hex(&self.ciphertext).expect("ciphertext");
        let iv: Vec<u8> = FromHex::from_hex(&self.cipherparams.iv).expect("iv");
        self.decrypt_data(key, &encrypted, &iv)
    }

    pub fn decrypt_enc_pair(&self, key: Key, enc_pair: &EncPair) -> Result<Vec<u8>> {
        let encrypted: Vec<u8> = FromHex::from_hex(&enc_pair.enc_str).unwrap();
        let iv: Vec<u8> = FromHex::from_hex(&enc_pair.nonce).unwrap();
        self.decrypt_data(key, &encrypted, &iv)
    }

    pub fn generate_derived_key(&self, key: &str) -> Result<Vec<u8>> {
        if let Some(ckd) = &self.cached_derived_key {
            ckd.get_derived_key(key)
        } else {
            let mut derived_key: Credential = [0u8; CREDENTIAL_LEN];
            self.kdfparams
                .generate_derived_key(key.as_bytes(), &mut derived_key);
            if !self.mac.is_empty() && !self.verify_derived_key(&derived_key) {
                return Err(Error::PasswordIncorrect);
            }
            Ok(derived_key.to_vec())
        }
    }

    pub fn verify_derived_key(&self, dk: &[u8]) -> bool {
        let cipher_bytes = Vec::from_hex(&self.ciphertext).expect("vec::from_hex");
        let mac = Self::generate_mac(dk, &cipher_bytes);
        self.mac == mac.to_hex()
    }

    fn generate_mac(derived_key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
        let result = [&derived_key[16..32], ciphertext].concat();
        let keccak256 = tiny_keccak::keccak256(&result);
        keccak256.to_vec()
    }

    fn decrypt_data(&self, key: Key, encrypted: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        let derived_key: Vec<u8> = match key {
            Key::Password(password) => {
                let dk = self.generate_derived_key(&password)?;
                if !self.verify_derived_key(&dk) {
                    return Err(Error::PasswordIncorrect);
                } else {
                    dk
                }
            }
            Key::DerivedKey(_dk) => {
                unimplemented!();
            }
        };

        let key = &derived_key[0..16];
        aes::ctr::decrypt_nopadding(encrypted, key, iv)
    }
}

pub fn random_iv(len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    thread_rng().fill_bytes(&mut v);
    v
}

pub fn hex_dsha256(hex: &str) -> String {
    let key_data: Vec<u8> = hex::decode(hex).expect("hex can't decode");
    hex::encode(dsha256(&key_data))
}

pub fn dsha256(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(&Sha256::digest(bytes)).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn decode_keystore_scrypt_test() {
        let data = r#"{
            "ciphertext": "008b7ec59042e19e09ede8758e53293afdc4dbcb3b1575e2452c25206aa3efc2",
            "mac": "085e95bd7c7b3045a0c8ca9d71ba03be7d0438cdae30b17779e3af0946554919",
            "cipher": "aes-128-ctr",
            "cipherparams": {
              "iv": "bff92d98914a498a7a1f5adfe81ec1c6"
            },
            "kdf": "scrypt",
            "kdfparams": {
              "dklen": 32,
              "n": 8192,
              "p": 1,
              "r": 8,
              "salt": "454a13723d41213de95af4135179fdc859517726c2be40752569e2c932557cc8"
            }
        }"#;

        let crypto: Crypto<SCryptParams> = serde_json::from_str(data).unwrap();
        let result = crypto
            .decrypt(Key::Password("Insecure Pa55w0rd".to_owned()))
            .unwrap();

        assert_eq!(
            hex::encode(result),
            "cce64585e3b15a0e4ee601a467e050c9504a0db69a559d7ec416fa25ad3410c2",
        );
    }

    #[test]
    pub fn decode_keystore_pbkdf2_test() {
        let data = r#"{
            "ciphertext": "d9b74342e4aefbe0e07dcb948b11099964f069cba69fdab32fcc08a14b25ce141b49dfc97924e9e2906242bb96e259017fcf783e7316c869136606ebea6b4dd66a7c9a6c27a12379dcd9e33979e085ad6be52b43ab98a0e809e40a0837a2535af4d3c511dba130ed2ea7e6366344c8",
            "mac": "58f2693a549e5728ee076762f15b514bd5f831529cc955433faf1bbf5924b0ac",
            "cipher": "aes-128-ctr",
            "cipherparams": {
                "iv": "c065d4ad065e0ce8e7239b275b4fad7c"
            },
            "kdf": "pbkdf2",
            "kdfparams": {
              "dklen": 32,
              "c": 10240,
              "prf": "hmac-sha256",
              "salt": "12349ed251de531b4fa971e33c0aed270911872c3032546194fa20595290d974"
            }
        }"#;

        let crypto: Crypto<Pbkdf2Params> = serde_json::from_str(data).unwrap();
        let cipher_bytes = crypto
            .decrypt(Key::Password("Insecure Pa55w0rd".to_owned()))
            .expect("cipher bytes");

        assert_eq!(
            String::from_utf8(cipher_bytes).unwrap(),
            "xprv9yrdwPSRnvomqFK4u1y5uW2SaXS2Vnr3pAYTjJjbyRZR8p9BwoadRsCxtgUFdAKeRPbwvGRcCSYMV69nNK4N2kadevJ6L5iQVy1SwGKDTHQ",
        );

        let ret = crypto.decrypt(Key::Password("WrongPassword".to_owned()));
        assert!(ret.is_err());
    }

    #[test]
    pub fn enc_pair_test() {
        let test_password = "Insecure Pa55w0rd".to_owned();

        let data = r#"{
            "ciphertext": "d9b74342e4aefbe0e07dcb948b11099964f069cba69fdab32fcc08a14b25ce141b49dfc97924e9e2906242bb96e259017fcf783e7316c869136606ebea6b4dd66a7c9a6c27a12379dcd9e33979e085ad6be52b43ab98a0e809e40a0837a2535af4d3c511dba130ed2ea7e6366344c8",
            "mac": "58f2693a549e5728ee076762f15b514bd5f831529cc955433faf1bbf5924b0ac",
            "cipher": "aes-128-ctr",
            "cipherparams": {
                "iv": "c065d4ad065e0ce8e7239b275b4fad7c"
            },
            "kdf": "pbkdf2",
            "kdfparams": {
              "dklen": 32,
              "c": 10240,
              "prf": "hmac-sha256",
              "salt": "12349ed251de531b4fa971e33c0aed270911872c3032546194fa20595290d974"
            }
        }"#;

        let enc_pair = EncPair {
            enc_str: "9ced11e88a971a5f690a6b4fc03cd40ccae5aef4cebee17e94f9dc3489d80d4a19f5980975b2a50ed242ae5260ad92852f46188cfbb08b9838e80e2eb0632dae956add53967b245e2edd".to_owned(),
            nonce: "19fde002b989ff9171a93a204cde9cee".to_owned(),
        };

        let crypto: Crypto<Pbkdf2Params> = serde_json::from_str(data).unwrap();
        let decrypted_bytes = crypto
            .decrypt_enc_pair(Key::Password(test_password), &enc_pair)
            .unwrap();
        let decrypted = String::from_utf8(decrypted_bytes).unwrap();

        assert_eq!(
            "inject kidney empty canal shadow pact comfort wife crush horse wife sketch",
            decrypted
        );

        let ret = crypto.decrypt_enc_pair(Key::Password("WrongPassword".to_owned()), &enc_pair);
        assert!(ret.is_err());
    }

    #[test]
    fn test_cache_derived_key() {
        let cdk = CacheDerivedKey::new("12345678", &[1, 1, 1, 1]);
        let ret = cdk.get_derived_key("1234");
        assert!(ret.is_err());
        assert_eq!(format!("{}", ret.err().unwrap()), "PasswordIncorrect");

        let ret = cdk.get_derived_key("12345678").unwrap();
        assert_eq!(hex::encode(ret), "01010101");
    }
}
