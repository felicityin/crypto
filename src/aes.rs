pub mod ctr {
    use crypto::aes::{ctr, KeySize::KeySize128};

    use crate::error::{Error, Result};

    pub fn encrypt_nopadding(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        if key.len() != 16 || iv.len() != 16 {
            return Err(Error::InvalidKeyIvLength);
        }
        let mut aes_enc = ctr(KeySize128, key, iv);
        let mut result = vec![0; data.len()];
        aes_enc.process(data, &mut result[..]);
        Ok(result)
    }

    pub fn decrypt_nopadding(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        if key.len() != 16 || iv.len() != 16 {
            return Err(Error::InvalidKeyIvLength);
        }
        let mut aes_enc = ctr(KeySize128, key, iv);
        let mut result = vec![0; data.len()];
        aes_enc.process(data, &mut result[..]);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use crate::aes::ctr::{decrypt_nopadding, encrypt_nopadding};
    use bitcoin_hashes::hex::ToHex;

    #[test]
    fn encrypt_nopadding_test() {
        let data = "TokenCoreX".as_bytes();
        let key = hex::decode("01020304010203040102030401020304").unwrap();
        let iv = hex::decode("01020304010203040102030401020304").unwrap();
        let ret = encrypt_nopadding(data, &key, &iv).expect("encrypt nopadding data");
        let ret_hex = ret.to_hex();

        assert_eq!("e19e6c5923d33c587cf8", ret_hex);

        let wrong_len_key = hex::decode("010203040102030401020304").unwrap();
        let ret = encrypt_nopadding(data, &wrong_len_key, &iv);
        assert!(ret.is_err());

        let wrong_len_iv = hex::decode("010203040102030401020304").unwrap();
        let ret = encrypt_nopadding(data, &key, &wrong_len_iv);
        assert!(ret.is_err());
    }

    #[test]
    fn decrypted_data_test() {
        let data = "TokenCoreX".as_bytes();
        let encrypted_data = hex::decode("e19e6c5923d33c587cf8").unwrap();
        let key = hex::decode("01020304010203040102030401020304").unwrap();
        let iv = hex::decode("01020304010203040102030401020304").unwrap();
        let ret = decrypt_nopadding(&encrypted_data, &key, &iv).expect("decrypted data error");

        assert_eq!(
            "TokenCoreX",
            String::from_utf8(ret).expect("decrypted failed")
        );

        let wrong_len_key = hex::decode("010203040102030401020304").unwrap();
        let ret = decrypt_nopadding(data, &wrong_len_key, &iv);
        assert!(ret.is_err());

        let wrong_len_iv = hex::decode("010203040102030401020304").unwrap();
        let ret = decrypt_nopadding(data, &key, &wrong_len_iv);
        assert!(ret.is_err());
    }
}
