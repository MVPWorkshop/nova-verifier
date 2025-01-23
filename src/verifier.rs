extern crate alloc;

use alloc::vec::Vec;
use ff::Field;
use nova_snark::{
    errors::NovaError,
    provider::{PallasEngine, VestaEngine},
    traits::Engine,
};
use serde::{Deserialize, Serialize};

use crate::deserializer::{
    deserialize_compressed_snark, deserialize_pubs, deserialize_vk, DeserializeError,
};

type EE<E> = nova_snark::provider::ipa_pc::EvaluationEngine<E>;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum NovaVerifierError {
    #[error("Deserialization error: {0}")]
    Deserialize(#[from] DeserializeError),
    // ! Seems like we are only using NovaError::ProofVerifyError
    #[error("Nova error: {0}")]
    Nova(#[from] NovaError),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum CurveName {
    Pallas,
    Vesta,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Pubs {
    pub first_curve: CurveName,
    pub num_of_steps: u32,
    pub num1: u32,
    pub num2: u32,
}

pub fn verify_nova(
    vk_bytes: &Vec<u8>,
    snark_bytes: &Vec<u8>,
    pubs_bytes: &Vec<u8>,
) -> Result<(), NovaVerifierError> {
    // ! TODO -> Pass num_of_steps and other 2 nums
    let pubs = deserialize_pubs(&pubs_bytes)?;
    match pubs.first_curve {
        CurveName::Pallas => verify_pallas_vesta(vk_bytes, snark_bytes),
        CurveName::Vesta => verify_vesta_pallas(vk_bytes, snark_bytes),
    }
}

pub fn verify_pallas_vesta(
    vk_bytes: &Vec<u8>,
    snark_bytes: &Vec<u8>,
) -> Result<(), NovaVerifierError> {
    verify_compressed_snark_pallas_vesta(vk_bytes, snark_bytes)
}

fn verify_compressed_snark_pallas_vesta(
    vk_bytes: &Vec<u8>,
    compressed_snark_bytes: &Vec<u8>,
) -> Result<(), NovaVerifierError> {
    let compressed_snark = deserialize_compressed_snark::<PallasEngine, VestaEngine, EE<_>, EE<_>>(
        &compressed_snark_bytes,
    )?;

    let mut vk = deserialize_vk::<PallasEngine, VestaEngine, EE<_>, EE<_>>(&vk_bytes)?;

    compressed_snark.verify(
        &mut vk,
        // ! NUMBER OF STEPS CAN NOT BE 0 !!!
        3,
        // TODO -> check if this is always ONE to ZERO
        &[<PallasEngine as Engine>::Scalar::ONE],
        &[<VestaEngine as Engine>::Scalar::ZERO],
    )?;
    Ok(())
}

pub fn verify_vesta_pallas(
    vk_bytes: &Vec<u8>,
    snark_bytes: &Vec<u8>,
) -> Result<(), NovaVerifierError> {
    verify_compressed_snark_vesta_pallas(vk_bytes, snark_bytes)
}

fn verify_compressed_snark_vesta_pallas(
    vk_bytes: &Vec<u8>,
    compressed_snark_bytes: &Vec<u8>,
) -> Result<(), NovaVerifierError>
where
{
    let compressed_snark = deserialize_compressed_snark::<VestaEngine, PallasEngine, EE<_>, EE<_>>(
        &compressed_snark_bytes,
    )?;

    let mut vk = deserialize_vk::<VestaEngine, PallasEngine, EE<_>, EE<_>>(&vk_bytes)?;

    compressed_snark.verify(
        &mut vk,
        // ! NUMBER OF STEPS CAN NOT BE 0 !!!
        3,
        // TODO -> check if this is always ONE to ZERO
        &[<VestaEngine as Engine>::Scalar::ONE],
        &[<PallasEngine as Engine>::Scalar::ZERO],
    )?;
    Ok(())
}
