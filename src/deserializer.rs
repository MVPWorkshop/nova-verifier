extern crate alloc;

use alloc::{vec, vec::Vec};
use core::marker::PhantomData;

// use core::error;
// use core::error::Error;

use thiserror::Error;

use nova_snark::{
    // errors::NovaError,
    frontend::{num::AllocatedNum, ConstraintSystem, SynthesisError},
    // provider::{ipa_pc::EvaluationEngine, PallasEngine, VestaEngine},
    traits::{
        circuit::{StepCircuit, TrivialCircuit},
        evaluation::EvaluationEngineTrait,
        Engine,
    },
    CompressedSNARK,
    VerifierKey,
};

use ff::PrimeField;

// type EE<E> = nova_snark::provider::ipa_pc::EvaluationEngine<E>;
// type EEPrime<E> = nova_snark::provider::hyperkzg::EvaluationEngine<E>;
type S<E, EE> = nova_snark::spartan::snark::RelaxedR1CSSNARK<E, EE>;
// type SPrime<E, EE> = nova_snark::spartan::ppsnark::RelaxedR1CSSNARK<E, EE>;

#[derive(Clone, Debug, Default)]
pub struct CubicCircuit<F: PrimeField> {
    _p: PhantomData<F>,
}

impl<F: PrimeField> StepCircuit<F> for CubicCircuit<F> {
    fn arity(&self) -> usize {
        1
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        // Consider a cubic equation: `x^3 + x + 5 = y`, where `x` and `y` are respectively the input and output.
        let x = &z[0];
        let x_sq = x.square(cs.namespace(|| "x_sq"))?;
        let x_cu = x_sq.mul(cs.namespace(|| "x_cu"), x)?;
        let y = AllocatedNum::alloc(cs.namespace(|| "y"), || {
            Ok(x_cu.get_value().unwrap() + x.get_value().unwrap() + F::from(5u64))
        })?;

        cs.enforce(
            || "y = x^3 + x + 5",
            |lc| {
                lc + x_cu.get_variable()
                    + x.get_variable()
                    + CS::one()
                    + CS::one()
                    + CS::one()
                    + CS::one()
                    + CS::one()
            },
            |lc| lc + CS::one(),
            |lc| lc + y.get_variable(),
        );

        Ok(vec![y])
    }
}

// impl<F: PrimeField> CubicCircuit<F> {
//     fn output(&self, z: &[F]) -> Vec<F> {
//         vec![z[0] * z[0] * z[0] + z[0] + F::from(5u64)]
//     }
// }

#[derive(Error, Debug)]
pub enum DeserializeError {
    // ! TODO -> move this in errors.rs and make it work properly
    #[error("Deserialization of proof failed")]
    InvalidProof,
    #[error("Deserialization of public inputs failed")]
    InvalidPubs,
}

// ! TODO -> Send it all together as a CompressedStark, instead of E1, E2, EE1, EE2
pub(crate) fn deserialize_compressed_snark<E1, E2, EE1, EE2>(
    compressed_snark_bytes: &Vec<u8>,
) -> Result<
    CompressedSNARK<
        E1,
        E2,
        TrivialCircuit<<E1 as Engine>::Scalar>,
        CubicCircuit<<E2 as Engine>::Scalar>,
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

pub(crate) fn deserialize_vk<E1, E2, EE1, EE2>(
    vk_bytes: &Vec<u8>,
) -> Result<
    VerifierKey<
        E1,
        E2,
        TrivialCircuit<<E1 as Engine>::Scalar>,
        CubicCircuit<<E2 as Engine>::Scalar>,
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
    postcard::from_bytes(&vk_bytes).map_err(|_| DeserializeError::InvalidProof)
}
