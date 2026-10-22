use thiserror::Error;

#[derive(Error, Debug)]
pub enum IamError {
    #[error("Key epoch shredded")]
    KeyEpochShredded,
    #[error("Not implemented")]
    NotImplemented,
}
