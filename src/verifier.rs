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
use std::eprintln;
use std::time::Instant;

pub fn verify_compressed_snark_pallas_vesta(
    vk_bytes: &[u8],
    compressed_snark_bytes: &[u8],
    num_of_steps: usize,
    z0_primary: PallasScalar,
) -> Result<(), NovaVerifierError> {
    let start_total = Instant::now();

    let start_deserialize_snark = Instant::now();
    let compressed_snark = deserialize_compressed_snark::<PallasEngine, VestaEngine, EE<_>, EE<_>>(
        compressed_snark_bytes,
    )?;
    let duration_deserialize_snark = start_deserialize_snark.elapsed();

    let start_deserialize_vk = Instant::now();
    let mut vk = deserialize_vk::<PallasEngine, VestaEngine, EE<_>, EE<_>>(vk_bytes)?;
    let duration_deserialize_vk = start_deserialize_vk.elapsed();

    let start_ck_primary = Instant::now();
    vk.vk_primary.vk_ee.ck_v.ck = CK_PRIMARY_PARSED.to_vec();
    let duration_ck_primary = start_ck_primary.elapsed();

    let start_ck_secondary = Instant::now();
    vk.vk_secondary.vk_ee.ck_v.ck = CK_SECONDARY_PARSED.to_vec();
    let duration_ck_secondary = start_ck_secondary.elapsed();

    let start_verify = Instant::now();
    compressed_snark.verify(&vk, num_of_steps, &[z0_primary])?;
    let duration_verify = start_verify.elapsed();

    let total_duration = start_total.elapsed();

    eprintln!(
        "deserialize_compressed_snark: {:?}",
        duration_deserialize_snark
    );
    eprintln!("deserialize_vk: {:?}", duration_deserialize_vk);
    eprintln!("get_ck_primary: {:?}", duration_ck_primary);
    eprintln!("get_ck_secondary: {:?}", duration_ck_secondary);
    eprintln!("compressed_snark.verify: {:?}", duration_verify);
    eprintln!("Total time: {:?}", total_duration);

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
                PallasAffine::from_bytes(&bytes.try_into().ok()?).into()
            })
            .collect()
    };
    pub static ref CK_SECONDARY_PARSED: Vec<VestaAffine> = {
        CK_SECONDARY
            .iter()
            .filter_map(|hex| {
                let bytes: [u8; 32] = hex::decode(hex).ok()?.try_into().ok()?;
                VestaAffine::from_bytes(&bytes.try_into().ok()?).into()
            })
            .collect()
    };
}
