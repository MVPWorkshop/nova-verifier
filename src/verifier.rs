extern crate alloc;

use crate::{
    ck_primary::CK_PRIMARY,
    ck_secondary::CK_SECONDARY,
    deserializer::{deserialize_compressed_snark, deserialize_pubs, deserialize_vk},
    errors::NovaVerifierError,
    pubs::{CurveName, Pubs, Z0Values},
};
use alloc::vec::Vec;
use ff::Field;
use halo2curves::group::GroupEncoding;
use lazy_static::lazy_static;
use nova_snark::{
    provider::{
        pasta::{
            pallas::{Affine as PallasAffine, Scalar as PallasScalar},
            vesta::{Affine as VestaAffine, Scalar as VestaScalar},
        },
        PallasEngine, VestaEngine,
    },
    traits::Engine,
};

type EE<E> = nova_snark::provider::ipa_pc::EvaluationEngine<E>;

pub fn verify_nova(
    vk_bytes: &[u8],
    snark_bytes: &[u8],
    pubs_bytes: &[u8],
) -> Result<(), NovaVerifierError> {
    let Pubs {
        first_curve,
        num_of_steps,
        z0_primary,
    } = deserialize_pubs(pubs_bytes)?;

    match first_curve {
        CurveName::Pallas => verify_compressed_snark_pallas_vesta(
            vk_bytes,
            snark_bytes,
            num_of_steps,
            get_z0::<PallasEngine>(z0_primary),
        ),
        CurveName::Vesta => verify_compressed_snark_vesta_pallas(
            vk_bytes,
            snark_bytes,
            num_of_steps,
            get_z0::<VestaEngine>(z0_primary),
        ),
    }
}

pub fn verify_compressed_snark_pallas_vesta(
    vk_bytes: &[u8],
    compressed_snark_bytes: &[u8],
    num_of_steps: usize,
    z0_primary: PallasScalar,
) -> Result<(), NovaVerifierError> {
    let compressed_snark = deserialize_compressed_snark::<PallasEngine, VestaEngine, EE<_>, EE<_>>(
        compressed_snark_bytes,
    )?;
    let mut vk = deserialize_vk::<PallasEngine, VestaEngine, EE<_>, EE<_>>(vk_bytes)?;

    vk.vk_primary.vk_ee.ck_v.ck = CK_PRIMARY_PARSED.to_vec();
    vk.vk_secondary.vk_ee.ck_v.ck = CK_SECONDARY_PARSED.to_vec();

    compressed_snark.verify(&vk, num_of_steps, &[z0_primary])?;
    Ok(())
}

pub fn verify_compressed_snark_vesta_pallas(
    vk_bytes: &[u8],
    compressed_snark_bytes: &[u8],
    num_of_steps: usize,
    z0_primary: VestaScalar,
) -> Result<(), NovaVerifierError>
where
{
    let compressed_snark = deserialize_compressed_snark::<VestaEngine, PallasEngine, EE<_>, EE<_>>(
        compressed_snark_bytes,
    )?;
    let mut vk = deserialize_vk::<VestaEngine, PallasEngine, EE<_>, EE<_>>(vk_bytes)?;

    vk.vk_primary.vk_ee.ck_v.ck = CK_SECONDARY_PARSED.to_vec();
    vk.vk_secondary.vk_ee.ck_v.ck = CK_PRIMARY_PARSED.to_vec();

    compressed_snark.verify(&vk, num_of_steps, &[z0_primary])?;
    Ok(())
}

fn get_z0<E: Engine>(z0: Z0Values) -> E::Scalar {
    match z0 {
        Z0Values::ZERO => E::Scalar::ZERO,
        Z0Values::ONE => E::Scalar::ONE,
    }
}

lazy_static! {
    pub static ref CK_PRIMARY_PARSED: Vec<PallasAffine> = {
        CK_PRIMARY
            .iter()
            .filter_map(|hex| {
                let bytes: [u8; 32] = hex::decode(hex).ok()?.try_into().ok()?;
                PallasAffine::from_bytes(&bytes.into()).into()
            })
            .collect()
    };
    pub static ref CK_SECONDARY_PARSED: Vec<VestaAffine> = {
        CK_SECONDARY
            .iter()
            .filter_map(|hex| {
                let bytes: [u8; 32] = hex::decode(hex).ok()?.try_into().ok()?;
                VestaAffine::from_bytes(&bytes.into()).into()
            })
            .collect()
    };
}
