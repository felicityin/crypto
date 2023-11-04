use serde::{Deserialize, Serialize};

use crate::kdf::{Crypto, EncPair, KdfParams, Pbkdf2Params, SCryptParams};
use crate::error::{Error, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WalletMeta {
    Pbkdf2WalletMeta(WalletMsg<Pbkdf2Params>),
    ScryptWalletMeta(WalletMsg<SCryptParams>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletMsg<T: KdfParams> {
    pub id:            String,
    pub version:       u64,
    pub crypto:        Crypto<T>,
    pub address:       String,
    pub enc_mnemonic:  EncPair,
    pub mnemonic_path: String,
    pub token_meta:    TokenMeta,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenMeta {
    pub name:          String,
    pub password_hint: Option<String>,
    pub chain_type:    ChainType,
    pub timestamp:     u64,
    pub network:       Option<Network>,
    pub source:        Source,
    pub mode:          Mode,
    pub seg_wit:       Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Network {
    Mainnet,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Source {
    Mnemonic,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ChainType {
    Bitcoin,
    Ethereum,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Mode {
    Normal,
}

impl WalletMeta {
    pub fn from_json(kdf: &str, data: &str) -> Result<WalletMeta> {
        match kdf {
            "pbkdf2" => {
                let wallet_meta: WalletMsg<Pbkdf2Params> = serde_json::from_str(data).unwrap();
                Ok(WalletMeta::Pbkdf2WalletMeta(wallet_meta))
            }
            "scrypt" => {
                let wallet_meta: WalletMsg<SCryptParams> = serde_json::from_str(data).unwrap();
                Ok(WalletMeta::ScryptWalletMeta(wallet_meta))
            }
            _ => Err(Error::InvalidKdf(kdf.to_owned())),
        }
    }

    pub fn address(&self) -> &str {
        match self {
            WalletMeta::Pbkdf2WalletMeta(w) => &w.address,
            WalletMeta::ScryptWalletMeta(w) => &w.address,
        }
    }

    pub fn version(&self) -> u64 {
        match self {
            WalletMeta::Pbkdf2WalletMeta(w) => w.version,
            WalletMeta::ScryptWalletMeta(w) => w.version,
        }
    }

    pub fn mnemonic_path(&self) -> &str {
        match self {
            WalletMeta::Pbkdf2WalletMeta(w) => &w.mnemonic_path,
            WalletMeta::ScryptWalletMeta(w) => &w.mnemonic_path,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn decode_pbkdf2_json() {
        let data = r#"{
            "id": "00b291c8-2419-43e3-8bbb-bbff8982564e",
            "version": 44,
            "crypto": {
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
            },
            "address": "12z6UzsA3tjpaeuvA2Zr9jwx19Azz74D6g",
            "encMnemonic": {
                "encStr": "9ced11e88a971a5f690a6b4fc03cd40ccae5aef4cebee17e94f9dc3489d80d4a19f5980975b2a50ed242ae5260ad92852f46188cfbb08b9838e80e2eb0632dae956add53967b245e2edd",
                "nonce": "19fde002b989ff9171a93a204cde9cee"
            },
            "mnemonicPath": "m/44'/0'/0'",
            "xpub": "xpub6CqzLtyKdJN53jPY13W6GdyB8ZGWuFZuBPU4Xh9DXm6Q1cULVLtsyfXSjx4G77rNdCRBgi83LByaWxjtDaZfLAKT6vFUq3EhPtNwTpJigx8",
            "info": {
                "curve": "spec256k1",
                "purpuse": "sign"
            },
            "tokenMeta": {
                "name": "HDMnemonicKeystore",
                "passwordHint": null,
                "chainType": "BITCOIN",
                "timestamp": 1689122458,
                "network": "MAINNET",
                "backup": [],
                "source": "MNEMONIC",
                "mode": "NORMAL",
                "walletType": "HD",
                "segWit": "NONE"
            }
        }"#;
        let wallet_meta = WalletMeta::from_json("pbkdf2", data).unwrap();
        assert_eq!(
            wallet_meta.address(),
            "12z6UzsA3tjpaeuvA2Zr9jwx19Azz74D6g".to_owned()
        );
    }

    #[test]
    pub fn decode_scrypt_json() {
        let data = r#"{
            "id": "477798a0-1e08-40f2-a581-910e0f402e00",
            "version": 3,
            "crypto": {
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
            },
            "address": "6031564e7b2f5cc33737807b2e58daff870b590b",
            "encMnemonic": {
                "encStr": "d85ed1aea3fb51f9f6268dab0fac2c50c2a5a59f70faf9c4cd796515d651d3199bd5887e3cc46cd1926b1be3098d305a936d9d8cb22f678f2ea5506845046c5835e732820604ea695343",
                "nonce": "a01e1f8dc13e5ebfebb3bbc067983c4c"
            },
            "mnemonicPath": "m/44'/60'/0'/0/0",
            "tokenMeta": {
                "name": "V3MnemonicKeystore",
                "passwordHint": null,
                "chainType": "ETHEREUM",
                "timestamp": 1689122691,
                "network": null,
                "backup": [],
                "source": "MNEMONIC",
                "mode": "NORMAL",
                "walletType": "V3",
                "segWit": null
            }
        }"#;
        let wallet_meta = WalletMeta::from_json("scrypt", data).unwrap();
        assert_eq!(
            wallet_meta.address(),
            "6031564e7b2f5cc33737807b2e58daff870b590b".to_owned()
        );
    }
}
