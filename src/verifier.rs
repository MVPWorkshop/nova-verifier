extern crate alloc;

use nova_snark::{
    provider::{PallasEngine, VestaEngine},
    traits::Engine,
};

use alloc::vec::Vec;
use ff::Field;
// use ff::PrimeField;

use crate::deserializer::{deserialize_compressed_snark, deserialize_vk, DeserializeError};

type EE<E> = nova_snark::provider::ipa_pc::EvaluationEngine<E>;

pub fn verify(vk_bytes: &Vec<u8>, snark_bytes: &Vec<u8>) -> Result<(), DeserializeError> {
    verify_compressed_snark::<PallasEngine, VestaEngine>(vk_bytes, snark_bytes)
}

pub fn verify_compressed_snark<E1, E2>(
    vk_bytes: &Vec<u8>,
    compressed_snark_bytes: &Vec<u8>,
) -> Result<(), DeserializeError>
where
    E1: Engine<Base = <E2 as Engine>::Scalar, Scalar = pasta_curves::Fq>,
    E2: Engine<Base = <E1 as Engine>::Scalar, Scalar = pasta_curves::Fp>,
{
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
            &[<E1 as Engine>::Scalar::ONE],
            &[<E2 as Engine>::Scalar::ZERO],
        )
        .unwrap();
    Ok(())
}
