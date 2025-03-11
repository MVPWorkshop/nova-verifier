#[cfg(test)]
mod tests {

    extern crate std;
    use crate::{
        deserializer::{self, deserialize_pubs, CubicCircuit},
        errors::DeserializeError,
        pubs::CurveName,
        verifier::verify_nova,
    };
    use ff::Field;
    use nova_snark::{
        nova::{CompressedSNARK, PublicParams, RecursiveSNARK, VerifierKey},
        provider::{PallasEngine, VestaEngine},
        traits::{
            circuit::{StepCircuit, TrivialCircuit},
            evaluation::EvaluationEngineTrait,
            snark::RelaxedR1CSSNARKTrait,
            Engine,
        },
    };
    use pasta_curves::{Fp, Fq};
    use std::{boxed::Box, format, fs, vec, vec::Vec};

    type EE<E> = nova_snark::provider::ipa_pc::EvaluationEngine<E>;
    type S<E, EE> = nova_snark::spartan::ppsnark::RelaxedR1CSSNARK<E, EE>;

    #[test]
    fn no_std_proof_gen_and_verify() {
        test_ivc_nontrivial_with_spark_compression_with::<PallasEngine, VestaEngine, EE<_>, EE<_>>(
        );
    }

    fn test_ivc_nontrivial_with_spark_compression_with<E1, E2, EE1, EE2>()
    where
        E1: Engine<Base = <E2 as Engine>::Scalar>,
        E2: Engine<Base = <E1 as Engine>::Scalar>,
        EE1: EvaluationEngineTrait<E1>,
        EE2: EvaluationEngineTrait<E2>,
    {
        let circuit_primary = TrivialCircuit::default();
        let circuit_secondary = CubicCircuit::default();

        // produce public parameters, which we'll use with a spark-compressed SNARK
        let pp = PublicParams::<
            E1,
            E2,
            TrivialCircuit<<E1 as Engine>::Scalar>,
            CubicCircuit<<E2 as Engine>::Scalar>,
        >::setup(
            &circuit_primary,
            &circuit_secondary,
            &*S::<E1, EE1>::ck_floor(),
            &*S::<E2, EE2>::ck_floor(),
        )
        .unwrap();

        let num_steps = 3;

        // produce a recursive SNARK
        let mut recursive_snark = RecursiveSNARK::<
            E1,
            E2,
            TrivialCircuit<<E1 as Engine>::Scalar>,
            CubicCircuit<<E2 as Engine>::Scalar>,
        >::new(
            &pp,
            &circuit_primary,
            &circuit_secondary,
            &[<E1 as Engine>::Scalar::ONE],
            &[<E2 as Engine>::Scalar::ZERO],
        )
        .unwrap();

        for _i in 0..num_steps {
            let res = recursive_snark.prove_step(&pp, &circuit_primary, &circuit_secondary);
            assert!(res.is_ok());
        }

        // verify the recursive SNARK
        let res = recursive_snark.verify(
            &pp,
            num_steps,
            &[<E1 as Engine>::Scalar::ONE],
            &[<E2 as Engine>::Scalar::ZERO],
        );
        assert!(res.is_ok());

        let (zn_primary, zn_secondary) = res.unwrap();

        // sanity: check the claimed output with a direct computation of the same
        assert_eq!(zn_primary, vec![<E1 as Engine>::Scalar::ONE]);
        let mut zn_secondary_direct = vec![<E2 as Engine>::Scalar::ZERO];
        for _i in 0..num_steps {
            zn_secondary_direct = CubicCircuit::default().output(&zn_secondary_direct);
        }
        assert_eq!(zn_secondary, zn_secondary_direct);
        assert_eq!(zn_secondary, vec![<E2 as Engine>::Scalar::from(2460515u64)]);

        // run the compressed snark with Spark compiler
        // produce the prover and verifier keys for compressed snark
        let (pk, vk) = CompressedSNARK::<_, _, _, _, S<E1, EE1>, S<E2, EE2>>::setup(&pp).unwrap();

        // produce a compressed SNARK
        let res = CompressedSNARK::<_, _, _, _, S<E1, EE1>, S<E2, EE2>>::prove(
            &pp,
            &pk,
            &recursive_snark,
        );
        assert!(res.is_ok());
        let compressed_snark = res.unwrap();

        let vk_bytes = postcard::to_allocvec(&vk).unwrap();
        std::fs::write("vk.bin", &vk_bytes).expect("Failed vk_after");
        let snark_bytes = postcard::to_allocvec(&compressed_snark).unwrap();
        std::fs::write("compressed_snark.bin", &snark_bytes).expect("Failed csnark");
        let pubs_bytes = handle_pubs("test").unwrap();

        verify_nova(&vk_bytes, &snark_bytes, &pubs_bytes).unwrap();

        // ! COMMENT THIS PART

        // // verify the compressed SNARK
        // let res = compressed_snark.verify(
        //     &vk,
        //     num_steps,
        //     &[<E1 as Engine>::Scalar::ONE],
        //     &[<E2 as Engine>::Scalar::ZERO],
        // );
        // assert!(res.is_ok());
    }

    #[test]
    fn test_success() -> Result<(), Box<dyn std::error::Error>> {
        test_full("test")?;
        test_full("test")?;
        // test_full("quadratic")?;
        Ok(())
    }

    #[test]
    fn test_bad_pubs_deserialization() -> Result<(), Box<dyn std::error::Error>> {
        test_pubs_deserialization_fails("test")?;
        // test_pubs_deserialization_fails("quadratic")?;
        Ok(())
    }

    #[test]
    fn test_bad_proof_deserialization() -> Result<(), Box<dyn std::error::Error>> {
        test_proof_deserialization_fails("test")?;
        // test_proof_deserialization_fails("quadratic")?;
        Ok(())
    }

    fn test_proof_deserialization_fails(path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let bin_path_compressed_snark = format!("./resources/{}/compressed_snark.bin", &path);
        let mut bytes_from_file_compressed_snark = fs::read(bin_path_compressed_snark)?;

        bytes_from_file_compressed_snark[11] = 11;

        let result =
            deserializer::deserialize_compressed_snark::<PallasEngine, VestaEngine, EE<_>, EE<_>>(
                &bytes_from_file_compressed_snark,
            );
        assert!(matches!(result, Err(DeserializeError::InvalidProof)));
        Ok(())
    }

    fn test_pubs_deserialization_fails(path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let bin_path_pubs = format!("./resources/{}/pubs.bin", &path);
        let mut bytes_from_file_pubs = fs::read(bin_path_pubs)?;
        bytes_from_file_pubs[0] += 11;
        let result = deserializer::deserialize_pubs(&bytes_from_file_pubs);
        assert!(matches!(result, Err(DeserializeError::InvalidPubs)));
        Ok(())
    }

    fn test_full(path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let vk_bytes;
        let snark_bytes;
        let pubs_bytes = handle_pubs(&path)?;
        let pubs = deserialize_pubs(&pubs_bytes)?;

        match pubs.first_curve {
            CurveName::Pallas => {
                vk_bytes = handle_vk::<
                    PallasEngine,
                    VestaEngine,
                    TrivialCircuit<Fq>,
                    CubicCircuit<Fp>,
                    EE<_>,
                    EE<_>,
                >(&path)?;

                snark_bytes = handle_compressed_snark::<
                    PallasEngine,
                    VestaEngine,
                    TrivialCircuit<Fq>,
                    CubicCircuit<Fp>,
                    EE<_>,
                    EE<_>,
                >(&path)?;
            }
            CurveName::Vesta => {
                vk_bytes = handle_vk::<
                    VestaEngine,
                    PallasEngine,
                    TrivialCircuit<Fp>,
                    CubicCircuit<Fq>,
                    EE<_>,
                    EE<_>,
                >(&path)?;
                snark_bytes = handle_compressed_snark::<
                    VestaEngine,
                    PallasEngine,
                    TrivialCircuit<Fp>,
                    CubicCircuit<Fq>,
                    EE<_>,
                    EE<_>,
                >(&path)?;
            }
        }
        verify_nova(&vk_bytes, &snark_bytes, &pubs_bytes)?;
        Ok(())
    }

    fn handle_pubs(path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let bin_path_pubs = format!("./resources/{}/pubs.bin", &path);
        // ! Read bytes from BIN file
        let bytes_from_file_pubs = fs::read(bin_path_pubs)?;
        // ! Just a check that it is in right format and it can be deserialized
        deserializer::deserialize_pubs(&bytes_from_file_pubs)?;
        Ok(bytes_from_file_pubs)
    }

    // ! Helper functions
    fn handle_vk<E1, E2, C1, C2, EE1, EE2>(
        path: &str,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>>
    where
        E1: Engine<Base = <E2 as Engine>::Scalar>,
        E2: Engine<Base = <E1 as Engine>::Scalar>,
        C1: StepCircuit<E1::Scalar>,
        C2: StepCircuit<E2::Scalar>,
        EE1: EvaluationEngineTrait<E1>,
        EE2: EvaluationEngineTrait<E2>,
    {
        // let bin_path_vk = format!("./resources/{}/vk.bin", &path);
        // // ! Read bytes from BIN file
        // let bytes_from_file_vk = fs::read(bin_path_vk)?;
        // // ! Just a check that it is in right format and it can be deserialized
        // deserializer::deserialize_vk::<E1, E2, EE1, EE2>(&bytes_from_file_vk)?;
        // Ok(bytes_from_file_vk)

        let json_path_vk = format!("./resources/{}/vk.json", &path);
        // ! Read from JSON to String
        let json_string_vk = fs::read_to_string(json_path_vk)?;

        // ! From string into Vk
        let json_data_vk: VerifierKey<E1, E2, C1, C2, S<E1, EE1>, S<E2, EE2>> =
            serde_json::from_str(&json_string_vk)?;
        // println!("{:?}", json_data_vk);
        panic!("OPA");

        // ! Serialize into Bytes
        let bytes_vk = postcard::to_allocvec(&json_data_vk)?;

        // ! Write bytes to BIN file
        let output_bin_path_vk = format!("./resources/{}/vk.bin", &path);
        fs::write(output_bin_path_vk.clone(), &bytes_vk)?;

        // ! Writes bytes to TXT file
        let bytes_string_vk = serde_json::to_string(&bytes_vk)?;
        let output_txt_path_vk = format!("./resources/{}/vk.txt", &path);
        fs::write(output_txt_path_vk, bytes_string_vk)?;

        // ! Read bytes from BIN file
        let bytes_from_file_vk = fs::read(output_bin_path_vk.clone())?;

        // ! Just a check that it is in right format and it can be deserialized
        deserializer::deserialize_vk::<E1, E2, EE1, EE2>(&bytes_from_file_vk)?;

        Ok(bytes_from_file_vk)
    }

    // ! Helper functions
    fn handle_compressed_snark<E1, E2, C1, C2, EE1, EE2>(
        path: &str,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>>
    where
        E1: Engine<Base = <E2 as Engine>::Scalar>,
        E2: Engine<Base = <E1 as Engine>::Scalar>,
        C1: StepCircuit<E1::Scalar>,
        C2: StepCircuit<E2::Scalar>,
        EE1: EvaluationEngineTrait<E1>,
        EE2: EvaluationEngineTrait<E2>,
    {
        // let bin_path_compressed_snark = format!("./resources/{}/compressed_snark.bin", &path);
        // // ! Read bytes from BIN file
        // let bytes_from_file_compressed_snark = fs::read(bin_path_compressed_snark)?;
        // // ! Just a check that it is in right format and it can be deserialized
        // deserializer::deserialize_compressed_snark::<E1, E2, EE1, EE2>(
        //     &bytes_from_file_compressed_snark,
        // )?;
        // Ok(bytes_from_file_compressed_snark)
        let json_path_compressed_snark = format!("./resources/{}/compressed_snark.json", &path);
        // ! Read from JSON to String
        let json_string_compressed_snark = fs::read_to_string(json_path_compressed_snark)?;

        // ! From string into CompressedSTARK
        let json_data_compressed_snark: CompressedSNARK<E1, E2, C1, C2, S<E1, EE1>, S<E2, EE2>> =
            serde_json::from_str(&json_string_compressed_snark)?;
        // println!("{:?}", json_data_compressed_snark);

        // ! Serialize into Bytes
        let bytes_compressed_snark = postcard::to_allocvec(&json_data_compressed_snark)?;
        // println!("{:?}", bytes_compressed_snark);

        // ! Write bytes to BIN file
        let output_bin_path_compressed_snark =
            format!("./resources/{}/compressed_snark.bin", &path);
        fs::write(
            output_bin_path_compressed_snark.clone(),
            &bytes_compressed_snark,
        )?;

        // ! Write bytes to TXT file
        let bytes_string_compressed_snark = serde_json::to_string(&bytes_compressed_snark)?;
        let output_txt_path_compressed_snark =
            format!("./resources/{}/compressed_snark.txt", &path);
        fs::write(
            output_txt_path_compressed_snark,
            bytes_string_compressed_snark,
        )?;

        // ! Read bytes from BIN file
        let bytes_from_file_compressed_snark = fs::read(output_bin_path_compressed_snark.clone())?;

        // ! Just a check that it is in right format and it can be deserialized
        deserializer::deserialize_compressed_snark::<E1, E2, EE1, EE2>(
            &bytes_from_file_compressed_snark,
        )?;

        Ok(bytes_from_file_compressed_snark)
    }
}
