use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("InvalidKeyIvLength")]
    InvalidKeyIvLength,

    #[error("KdfParamsInvalid")]
    KdfParamsInvalid,

    #[error("PasswordIncorrect")]
    PasswordIncorrect,

    #[error("Invalid kdf: {0}")]
    InvalidKdf(String),

    #[error("Wallet meta was not found: {0}")]
    WalletMetaNotFound(String),
}
