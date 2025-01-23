#[cfg(test)]
mod tests {

    extern crate std;
    use std::{boxed::Box, format, fs, vec::Vec};

    use nova_snark::{
        provider::{PallasEngine, VestaEngine},
        traits::{
            circuit::{GenericCircuit, StepCircuit},
            evaluation::EvaluationEngineTrait,
            Engine,
        },
        CompressedSNARK, VerifierKey,
    };
    use pasta_curves::{Fp, Fq};

    use crate::{
        deserializer::{self, deserialize_pubs},
        verifier::{verify_nova, CurveName, Pubs},
    };

    type EE<E> = nova_snark::provider::ipa_pc::EvaluationEngine<E>;
    type S<E, EE> = nova_snark::spartan::snark::RelaxedR1CSSNARK<E, EE>;

    #[test]
    fn test() -> Result<(), Box<dyn std::error::Error>> {
        test_full("quadratic")?;
        test_full("cubic")?;
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
        let json_path_pubs = format!("./src/resources/json/{}/pubs.json", &path);

        let json_string_pubs = fs::read_to_string(json_path_pubs)?;

        // ! From string into Pubs
        let json_data_pubs: Pubs = serde_json::from_str(&json_string_pubs)?;

        // ! Serialize into Bytes
        let bytes_pubs = postcard::to_allocvec(&json_data_pubs)?;
        // println!("{:?}", bytes_pubs.len());

        // ! Write bytes to file
        let output_bin_path_pubs = format!("./src/resources/bin/{}/pubs.bin", &path);
        fs::write(output_bin_path_pubs.clone(), &bytes_pubs)?;

        let bytes_string_pubs = serde_json::to_string(&bytes_pubs)?;
        let output_txt_path_pubs = format!("./src/resources/txt/{}/pubs.txt", &path);
        fs::write(output_txt_path_pubs.clone(), bytes_string_pubs)?;

        // ! Read bytes from file
        let bytes_from_file_pubs = fs::read(output_bin_path_pubs.clone())?;

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
        let json_path_vk = format!("./src/resources/json/{}/vk.json", &path);
        // ! Read from JSON to String
        let json_string_vk = fs::read_to_string(json_path_vk)?;

        // ! From string into Vk
        let json_data_vk: VerifierKey<E1, E2, C1, C2, S<E1, EE1>, S<E2, EE2>> =
            serde_json::from_str(&json_string_vk)?;
        // println!("{:?}", json_data_vk);

        // ! Serialize into Bytes
        let bytes_vk = postcard::to_allocvec(&json_data_vk)?;

        // ! Write bytes to BIN file
        let output_bin_path_vk = format!("./src/resources/bin/{}/vk.bin", &path);
        fs::write(output_bin_path_vk.clone(), &bytes_vk)?;

        // ! Writes bytes to TXT file
        let bytes_string_vk = serde_json::to_string(&bytes_vk)?;
        let output_txt_path_vk = format!("./src/resources/txt/{}/vk.txt", &path);
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
        let json_path_compressed_snark =
            format!("./src/resources/json/{}/compressed_snark.json", &path);
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
            format!("./src/resources/bin/{}/compressed_snark.bin", &path);
        fs::write(
            output_bin_path_compressed_snark.clone(),
            &bytes_compressed_snark,
        )?;

        // ! Write bytes to TXT file
        let bytes_string_compressed_snark = serde_json::to_string(&bytes_compressed_snark)?;
        let output_txt_path_compressed_snark =
            format!("./src/resources/txt/{}/compressed_snark.txt", &path);
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
