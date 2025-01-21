#[cfg(test)]
mod tests {

    extern crate std;
    use std::{fs, vec::Vec};

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
    fn test() {
        let vk_bytes;
        let snark_bytes;
        let pubs_bytes = handle_pubs();
        let pubs = deserialize_pubs(&pubs_bytes).unwrap();

        match pubs.first_curve {
            CurveName::Pallas => {
                vk_bytes = handle_vk::<
                    PallasEngine,
                    VestaEngine,
                    GenericCircuit<Fq>,
                    GenericCircuit<Fp>,
                    EE<_>,
                    EE<_>,
                >();
                snark_bytes = handle_compressed_snark::<
                    PallasEngine,
                    VestaEngine,
                    GenericCircuit<Fq>,
                    GenericCircuit<Fp>,
                    EE<_>,
                    EE<_>,
                >();
            }
            CurveName::Vesta => {
                vk_bytes = handle_vk::<
                    VestaEngine,
                    PallasEngine,
                    GenericCircuit<Fp>,
                    GenericCircuit<Fq>,
                    EE<_>,
                    EE<_>,
                >();
                snark_bytes = handle_compressed_snark::<
                    VestaEngine,
                    PallasEngine,
                    GenericCircuit<Fp>,
                    GenericCircuit<Fq>,
                    EE<_>,
                    EE<_>,
                >();
            }
        }
        verify_nova(&vk_bytes, &snark_bytes, &pubs_bytes).unwrap();
    }

    fn handle_pubs() -> Vec<u8> {
        let json_path_pubs = "./src/resources/json/pubs.json";

        let json_string_pubs =
            fs::read_to_string(json_path_pubs).expect("Failed to read JSON file");

        // ! From string into Pubs
        let json_data_pubs: Pubs =
            serde_json::from_str(&json_string_pubs).expect("Failed to parse JSON");

        // ! Serialize into Bytes
        let bytes_pubs = postcard::to_allocvec(&json_data_pubs).unwrap();
        // println!("{:?}", bytes_pubs.len());

        // ! Write bytes to file
        let output_path_pubs = "./src/resources/bin/pubs.bin";
        fs::write(output_path_pubs, bytes_pubs).expect("Failed to write binary file");
        // ! Read bytes from file
        let bytes_from_file_pubs = fs::read(output_path_pubs).unwrap();

        // ! Just a check that it is in right format and it can be deserialized
        let _deserialized_value_pubs =
            deserializer::deserialize_pubs(&bytes_from_file_pubs).unwrap();

        bytes_from_file_pubs
    }

    // ! Helper functions
    fn handle_vk<E1, E2, C1, C2, EE1, EE2>() -> Vec<u8>
    where
        E1: Engine<Base = <E2 as Engine>::Scalar>,
        E2: Engine<Base = <E1 as Engine>::Scalar>,
        C1: StepCircuit<E1::Scalar>,
        C2: StepCircuit<E2::Scalar>,
        EE1: EvaluationEngineTrait<E1>,
        EE2: EvaluationEngineTrait<E2>,
    {
        let json_path_vk = "./src/resources/json/vk.json";
        // ! Read from JSON to String
        let json_string_vk = fs::read_to_string(json_path_vk).expect("Failed to read JSON file");

        // ! From string into CompressedSTARK
        let json_data_vk: VerifierKey<E1, E2, C1, C2, S<E1, EE1>, S<E2, EE2>> =
            serde_json::from_str(&json_string_vk).expect("Failed to parse JSON");
        // println!("{:?}", json_data_vk);

        // ! Serialize into Bytes
        let bytes_vk = postcard::to_allocvec(&json_data_vk).unwrap();
        // println!("{:?}", bytes_vk.len());

        // ! Write bytes to file
        let output_path_vk = "./src/resources/bin/vk.bin";
        fs::write(output_path_vk, bytes_vk).expect("Failed to write binary file");
        // ! Read bytes from file
        let bytes_from_file_vk = fs::read(output_path_vk).unwrap();

        // ! Just a check that it is in right format and it can be deserialized
        let _deserialized_value_vk =
            deserializer::deserialize_vk::<E1, E2, EE1, EE2>(&bytes_from_file_vk).unwrap();

        bytes_from_file_vk
    }

    // ! Helper functions
    fn handle_compressed_snark<E1, E2, C1, C2, EE1, EE2>() -> Vec<u8>
    where
        E1: Engine<Base = <E2 as Engine>::Scalar>,
        E2: Engine<Base = <E1 as Engine>::Scalar>,
        C1: StepCircuit<E1::Scalar>,
        C2: StepCircuit<E2::Scalar>,
        EE1: EvaluationEngineTrait<E1>,
        EE2: EvaluationEngineTrait<E2>,
    {
        let json_path_compressed_snark = "./src/resources/json/compressed_snark.json";
        // ! Read from JSON to String
        let json_string_compressed_snark =
            fs::read_to_string(json_path_compressed_snark).expect("Failed to read JSON file");

        // ! From string into CompressedSTARK
        let json_data_compressed_snark: CompressedSNARK<E1, E2, C1, C2, S<E1, EE1>, S<E2, EE2>> =
            serde_json::from_str(&json_string_compressed_snark).expect("Failed to parse JSON");
        // println!("{:?}", json_data_compressed_snark);

        // ! Serialize into Bytes
        let bytes_compressed_snark = postcard::to_allocvec(&json_data_compressed_snark).unwrap();
        // println!("{:?}", bytes_compressed_snark);

        // ! Write bytes to file
        let output_path_compressed_snark = "./src/resources/bin/compressed_snark.bin";
        fs::write(output_path_compressed_snark, bytes_compressed_snark)
            .expect("Failed to write binary file");
        // ! Read bytes from file
        let bytes_from_file_compressed_snark = fs::read(output_path_compressed_snark).unwrap();

        // ! Just a check that it is in right format and it can be deserialized
        let _deserialized_value_compressed_snark =
            deserializer::deserialize_compressed_snark::<E1, E2, EE1, EE2>(
                &bytes_from_file_compressed_snark,
            )
            .unwrap();

        bytes_from_file_compressed_snark
    }
}
