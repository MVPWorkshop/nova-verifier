#[cfg(test)]
mod tests {

    extern crate std;
    use crate::{
        deserializer::{self, deserialize_pubs},
        errors::DeserializeError,
        pubs::CurveName,
        verifier::verify_nova,
    };
    use no_std_nova_snark::{
        provider::{PallasEngine, VestaEngine},
        traits::{
            circuit::{GenericCircuit, StepCircuit},
            evaluation::EvaluationEngineTrait,
            Engine,
        },
    };
    use pasta_curves::{Fp, Fq};
    use std::{boxed::Box, format, fs, vec::Vec};

    type EE<E> = no_std_nova_snark::provider::ipa_pc::EvaluationEngine<E>;

    #[test]
    fn test_success() -> Result<(), Box<dyn std::error::Error>> {
        test_full("cubic")?;
        test_full("cubic")?;
        // test_full("quadratic")?;
        Ok(())
    }

    #[test]
    fn test_bad_pubs_deserialization() -> Result<(), Box<dyn std::error::Error>> {
        test_pubs_deserialization_fails("cubic")?;
        // test_pubs_deserialization_fails("quadratic")?;
        Ok(())
    }

    #[test]
    fn test_bad_proof_deserialization() -> Result<(), Box<dyn std::error::Error>> {
        test_proof_deserialization_fails("cubic")?;
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
                    GenericCircuit<Fq>,
                    GenericCircuit<Fp>,
                    EE<_>,
                    EE<_>,
                >(&path)?;
                snark_bytes = handle_compressed_snark::<
                    PallasEngine,
                    VestaEngine,
                    GenericCircuit<Fq>,
                    GenericCircuit<Fp>,
                    EE<_>,
                    EE<_>,
                >(&path)?;
            }
            CurveName::Vesta => {
                vk_bytes = handle_vk::<
                    VestaEngine,
                    PallasEngine,
                    GenericCircuit<Fp>,
                    GenericCircuit<Fq>,
                    EE<_>,
                    EE<_>,
                >(&path)?;
                snark_bytes = handle_compressed_snark::<
                    VestaEngine,
                    PallasEngine,
                    GenericCircuit<Fp>,
                    GenericCircuit<Fq>,
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

    use pasta_curves::EpAffine;

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
        let bin_path_vk = format!("./vk_fixed.bin");
        // ! Read bytes from BIN file
        let bytes_from_file_vk = fs::read(bin_path_vk)?;
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
        let bin_path_compressed_snark = format!("./resources/{}/compressed_snark.bin", &path);
        // ! Read bytes from BIN file
        let bytes_from_file_compressed_snark = fs::read(bin_path_compressed_snark)?;
        // ! Just a check that it is in right format and it can be deserialized
        deserializer::deserialize_compressed_snark::<E1, E2, EE1, EE2>(
            &bytes_from_file_compressed_snark,
        )?;
        Ok(bytes_from_file_compressed_snark)
    }
}
