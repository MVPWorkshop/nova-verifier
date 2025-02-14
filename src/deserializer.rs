extern crate alloc;

use crate::{errors::DeserializeError, pubs::Pubs};
use alloc::vec::Vec;
use no_std_nova_snark::{
    traits::{circuit::GenericCircuit, evaluation::EvaluationEngineTrait, Engine},
    CompressedSNARK, VerifierKey,
};

type S<E, EE> = no_std_nova_snark::spartan::ppsnark::RelaxedR1CSSNARK<E, EE>;

pub fn deserialize_pubs(pubs_bytes: &Vec<u8>) -> Result<Pubs, DeserializeError> {
    postcard::from_bytes(&pubs_bytes).map_err(|_| DeserializeError::InvalidPubs)
}

pub fn deserialize_compressed_snark<E1, E2, EE1, EE2>(
    compressed_snark_bytes: &Vec<u8>,
) -> Result<
    CompressedSNARK<
        E1,
        E2,
        GenericCircuit<<E1 as Engine>::Scalar>,
        GenericCircuit<<E2 as Engine>::Scalar>,
        S<E1, EE1>,
        S<E2, EE2>,
    >,
    DeserializeError,
>
where
    E1: Engine<Base = <E2 as Engine>::Scalar>,
    E2: Engine<Base = <E1 as Engine>::Scalar>,

    EE1: EvaluationEngineTrait<E1>,
    EE2: EvaluationEngineTrait<E2>,
{
    postcard::from_bytes(&compressed_snark_bytes).map_err(|_| DeserializeError::InvalidProof)
}

pub fn deserialize_vk<E1, E2, EE1, EE2>(
    vk_bytes: &Vec<u8>,
) -> Result<
    VerifierKey<
        E1,
        E2,
        GenericCircuit<<E1 as Engine>::Scalar>,
        GenericCircuit<<E2 as Engine>::Scalar>,
        S<E1, EE1>,
        S<E2, EE2>,
    >,
    DeserializeError,
>
where
    E1: Engine<Base = <E2 as Engine>::Scalar>,
    E2: Engine<Base = <E1 as Engine>::Scalar>,

    EE1: EvaluationEngineTrait<E1>,
    EE2: EvaluationEngineTrait<E2>,
{
    postcard::from_bytes(&vk_bytes).map_err(|_| DeserializeError::InvalidVerifyingKey)
}
