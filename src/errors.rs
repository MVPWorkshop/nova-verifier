use no_std_nova_snark::errors::NovaError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DeserializeError {
    #[error("Deserialization of proof failed")]
    InvalidProof,
    #[error("Deserialization of public inputs failed")]
    InvalidPubs,
    #[error("Deserialization of verification key failed")]
    InvalidVerifyingKey,
}

#[derive(Error, Debug)]
pub enum NovaVerifierError {
    #[error("Deserialization error: {0}")]
    Deserialize(#[from] DeserializeError),
    // ! Seems like we are only using NovaError::ProofVerifyError
    #[error("Nova error: {0}")]
    Nova(#[from] NovaError),
}
