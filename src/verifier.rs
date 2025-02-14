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
use no_std_nova_snark::{
    provider::{PallasEngine, VestaEngine},
    traits::Engine,
};
use pasta_curves::{
    group::GroupEncoding, pallas::Scalar as PallasScalar, vesta::Scalar as VestaScalar, EpAffine,
    EqAffine,
};

type EE<E> = no_std_nova_snark::provider::ipa_pc::EvaluationEngine<E>;

pub fn verify_nova(
    vk_bytes: &Vec<u8>,
    snark_bytes: &Vec<u8>,
    pubs_bytes: &Vec<u8>,
) -> Result<(), NovaVerifierError> {
    let Pubs {
        first_curve,
        num_of_steps,
        z0_primary,
        z0_secondary,
    } = deserialize_pubs(&pubs_bytes)?;

    match first_curve {
        CurveName::Pallas => verify_compressed_snark_pallas_vesta(
            vk_bytes,
            snark_bytes,
            num_of_steps,
            get_z0::<PallasEngine>(z0_primary),
            get_z0::<VestaEngine>(z0_secondary),
        ),
        CurveName::Vesta => verify_compressed_snark_vesta_pallas(
            vk_bytes,
            snark_bytes,
            num_of_steps,
            get_z0::<VestaEngine>(z0_primary),
            get_z0::<PallasEngine>(z0_secondary),
        ),
    }
}

pub fn verify_compressed_snark_pallas_vesta(
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

    vk.vk_primary.vk_ee.ck_v.ck = get_ck_primary();
    vk.vk_secondary.vk_ee.ck_v.ck = get_ck_secondary();

    compressed_snark.verify(&mut vk, num_of_steps, &[z0_primary], &[z0_secondary])?;
    Ok(())
}

pub fn verify_compressed_snark_vesta_pallas(
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

    vk.vk_primary.vk_ee.ck_v.ck = get_ck_secondary();
    vk.vk_secondary.vk_ee.ck_v.ck = get_ck_primary();

    compressed_snark.verify(&mut vk, num_of_steps, &[z0_primary], &[z0_secondary])?;
    Ok(())
}

fn get_ck_primary() -> Vec<EpAffine> {
    CK_PRIMARY
        .iter()
        .filter_map(|hex| {
            let bytes = hex::decode(hex).ok()?;
            EpAffine::from_bytes(&bytes.try_into().ok()?).into()
        })
        .collect()
}

fn get_ck_secondary() -> Vec<EqAffine> {
    CK_SECONDARY
        .iter()
        .filter_map(|hex| {
            let bytes = hex::decode(hex).ok()?;
            EqAffine::from_bytes(&bytes.try_into().ok()?).into()
        })
        .collect()
}

fn get_z0<E: Engine>(z0: Z0Values) -> E::Scalar {
    match z0 {
        Z0Values::ZERO => E::Scalar::ZERO,
        Z0Values::ONE => E::Scalar::ONE,
    }
}
