extern crate alloc;

use alloc::vec::Vec;
use ff::Field;
use nova_snark::{
    provider::{PallasEngine, VestaEngine},
    traits::Engine,
};
use serde::{Deserialize, Serialize};

use crate::deserializer::{
    deserialize_compressed_snark, deserialize_pubs, deserialize_vk, DeserializeError,
};

type EE<E> = nova_snark::provider::ipa_pc::EvaluationEngine<E>;

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
) -> Result<(), DeserializeError> {
    // ! TODO -> Remove unwraps in all code !!!
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
) -> Result<(), DeserializeError> {
    verify_compressed_snark_pallas_vesta(vk_bytes, snark_bytes)
}

fn verify_compressed_snark_pallas_vesta(
    vk_bytes: &Vec<u8>,
    compressed_snark_bytes: &Vec<u8>,
) -> Result<(), DeserializeError> {
    let compressed_snark = deserialize_compressed_snark::<PallasEngine, VestaEngine, EE<_>, EE<_>>(
        &compressed_snark_bytes,
    )?;

    let mut vk = deserialize_vk::<PallasEngine, VestaEngine, EE<_>, EE<_>>(&vk_bytes)?;

    // ! TODO -> map_err with Nova error !!!
    compressed_snark
        .verify(
            &mut vk,
            // ! NUMBER OF STEPS CAN NOT BE 0 !!!
            3,
            &[<PallasEngine as Engine>::Scalar::ONE],
            &[<VestaEngine as Engine>::Scalar::ZERO],
        )
        .unwrap();
    Ok(())
}

pub fn verify_vesta_pallas(
    vk_bytes: &Vec<u8>,
    snark_bytes: &Vec<u8>,
) -> Result<(), DeserializeError> {
    verify_compressed_snark_vesta_pallas(vk_bytes, snark_bytes)
}

fn verify_compressed_snark_vesta_pallas(
    vk_bytes: &Vec<u8>,
    compressed_snark_bytes: &Vec<u8>,
) -> Result<(), DeserializeError>
where
{
    let compressed_snark = deserialize_compressed_snark::<VestaEngine, PallasEngine, EE<_>, EE<_>>(
        &compressed_snark_bytes,
    )?;

    let mut vk = deserialize_vk::<VestaEngine, PallasEngine, EE<_>, EE<_>>(&vk_bytes)?;

    // ! TODO -> map_err with Nova error !!!
    compressed_snark
        .verify(
            &mut vk,
            // ! NUMBER OF STEPS CAN NOT BE 0 !!!
            3,
            &[<VestaEngine as Engine>::Scalar::ONE],
            &[<PallasEngine as Engine>::Scalar::ZERO],
        )
        .unwrap();
    Ok(())
}
