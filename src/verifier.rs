extern crate alloc;

use crate::deserializer::{
    deserialize_compressed_snark, deserialize_pubs, deserialize_vk, DeserializeError,
};
use alloc::vec::Vec;
use ff::Field;
use nova_snark::{
    errors::NovaError,
    provider::{PallasEngine, VestaEngine},
    traits::Engine,
};
use pasta_curves::pallas::Scalar as PallasScalar;
use pasta_curves::vesta::Scalar as VestaScalar;
use serde::{Deserialize, Serialize};
use thiserror::Error;

type EE<E> = nova_snark::provider::ipa_pc::EvaluationEngine<E>;

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
pub enum Z0Values {
    ZERO = 0,
    ONE = 1,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Pubs {
    pub first_curve: CurveName,
    pub num_of_steps: usize,
    pub z0_primary: Z0Values,
    pub z0_secondary: Z0Values,
}

pub fn verify_nova(
    vk_bytes: &Vec<u8>,
    snark_bytes: &Vec<u8>,
    pubs_bytes: &Vec<u8>,
) -> Result<(), NovaVerifierError> {
    // ! TODO -> Pass num_of_steps and other 2 nums
    let Pubs {
        first_curve,
        num_of_steps,
        z0_primary,
        z0_secondary,
    } = deserialize_pubs(&pubs_bytes)?;

    match first_curve {
        CurveName::Pallas => {
            let z0_primary = match z0_primary {
                Z0Values::ZERO => <PallasEngine as Engine>::Scalar::ZERO,
                Z0Values::ONE => <PallasEngine as Engine>::Scalar::ONE,
            };

            let z0_secondary = match z0_secondary {
                Z0Values::ZERO => <VestaEngine as Engine>::Scalar::ZERO,
                Z0Values::ONE => <VestaEngine as Engine>::Scalar::ONE,
            };
            verify_pallas_vesta(
                vk_bytes,
                snark_bytes,
                num_of_steps,
                z0_primary,
                z0_secondary,
            )
        }
        CurveName::Vesta => {
            let z0_primary = match z0_primary {
                Z0Values::ZERO => <VestaEngine as Engine>::Scalar::ZERO,
                Z0Values::ONE => <VestaEngine as Engine>::Scalar::ONE,
            };
            let z0_secondary = match z0_secondary {
                Z0Values::ZERO => <PallasEngine as Engine>::Scalar::ZERO,
                Z0Values::ONE => <PallasEngine as Engine>::Scalar::ONE,
            };

            verify_vesta_pallas(
                vk_bytes,
                snark_bytes,
                num_of_steps,
                z0_primary,
                z0_secondary,
            )
        }
    }
}

pub fn verify_pallas_vesta(
    vk_bytes: &Vec<u8>,
    snark_bytes: &Vec<u8>,
    num_of_steps: usize,
    z0_primary: PallasScalar,
    z0_secondary: VestaScalar,
) -> Result<(), NovaVerifierError> {
    verify_compressed_snark_pallas_vesta(
        vk_bytes,
        snark_bytes,
        num_of_steps,
        z0_primary,
        z0_secondary,
    )
}

fn verify_compressed_snark_pallas_vesta(
    vk_bytes: &Vec<u8>,
    compressed_snark_bytes: &Vec<u8>,
    num_of_steps: usize,
    z0_primary: PallasScalar,
    z0_secondary: VestaScalar,
) -> Result<(), NovaVerifierError> {
    let compressed_snark = deserialize_compressed_snark::<PallasEngine, VestaEngine, EE<_>, EE<_>>(
        &compressed_snark_bytes,
    )?;

    let mut vk = deserialize_vk::<PallasEngine, VestaEngine, EE<_>, EE<_>>(&vk_bytes)?;

    compressed_snark.verify(
        &mut vk,
        num_of_steps,
        // TODO -> check if this is always ONE to ZERO
        &[z0_primary],
        &[z0_secondary],
    )?;
    Ok(())
}

pub fn verify_vesta_pallas(
    vk_bytes: &Vec<u8>,
    snark_bytes: &Vec<u8>,
    num_of_steps: usize,
    z0_primary: VestaScalar,
    z0_secondary: PallasScalar,
) -> Result<(), NovaVerifierError> {
    verify_compressed_snark_vesta_pallas(
        vk_bytes,
        snark_bytes,
        num_of_steps,
        z0_primary,
        z0_secondary,
    )
}

fn verify_compressed_snark_vesta_pallas(
    vk_bytes: &Vec<u8>,
    compressed_snark_bytes: &Vec<u8>,
    num_of_steps: usize,
    z0_primary: VestaScalar,
    z0_secondary: PallasScalar,
) -> Result<(), NovaVerifierError>
where
{
    let compressed_snark = deserialize_compressed_snark::<VestaEngine, PallasEngine, EE<_>, EE<_>>(
        &compressed_snark_bytes,
    )?;

    let mut vk = deserialize_vk::<VestaEngine, PallasEngine, EE<_>, EE<_>>(&vk_bytes)?;

    compressed_snark.verify(
        &mut vk,
        num_of_steps,
        // TODO -> check if this is always ONE to ZERO
        &[z0_primary],
        &[z0_secondary],
    )?;
    Ok(())
}
