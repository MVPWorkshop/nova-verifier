mod tests {
    use std::{fs, marker::PhantomData};

    use nova_snark::{
        frontend::{num::AllocatedNum, ConstraintSystem, SynthesisError},
        provider::{ipa_pc::EvaluationEngine, PallasEngine, VestaEngine},
        traits::{
            circuit::{StepCircuit, TrivialCircuit},
            evaluation::EvaluationEngineTrait,
            Engine,
        },
        CompressedSNARK, VerifierKey,
    };

    use ff::PrimeField;

    use crate::{
        deserializer,
        verifier::{self, verify_compressed_snark},
    };

    type EE<E> = nova_snark::provider::ipa_pc::EvaluationEngine<E>;
    type EEPrime<E> = nova_snark::provider::hyperkzg::EvaluationEngine<E>;
    type S<E, EE> = nova_snark::spartan::snark::RelaxedR1CSSNARK<E, EE>;
    type SPrime<E, EE> = nova_snark::spartan::ppsnark::RelaxedR1CSSNARK<E, EE>;

    #[derive(Clone, Debug, Default)]
    struct CubicCircuit<F: PrimeField> {
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

    impl<F: PrimeField> CubicCircuit<F> {
        fn output(&self, z: &[F]) -> Vec<F> {
            vec![z[0] * z[0] * z[0] + z[0] + F::from(5u64)]
        }
    }

    #[test]
    fn test() {
        let compressed_snark = handle_compressed_snark::<PallasEngine, VestaEngine, EE<_>, EE<_>>();
        let vk = handle_vk::<PallasEngine, VestaEngine, EE<_>, EE<_>>();
        verify_compressed_snark::<PallasEngine, VestaEngine>(&vk, &compressed_snark).unwrap();
    }

    // ! Helper functions
    fn handle_vk<E1, E2, EE1, EE2>() -> Vec<u8>
    where
        E1: Engine<Base = <E2 as Engine>::Scalar>,
        E2: Engine<Base = <E1 as Engine>::Scalar>,
        EE1: EvaluationEngineTrait<E1>,
        EE2: EvaluationEngineTrait<E2>,
    {
        let json_path_vk = "./src/resources/json/vk.json";
        // ! Read from JSON to String
        let json_string_vk = fs::read_to_string(json_path_vk).expect("Failed to read JSON file");

        // ! From string into CompressedSTARK
        let json_data_vk: VerifierKey<
            E1,
            E2,
            TrivialCircuit<<E1 as Engine>::Scalar>,
            CubicCircuit<<E2 as Engine>::Scalar>,
            S<E1, EE1>,
            S<E2, EE2>,
        > = serde_json::from_str(&json_string_vk).expect("Failed to parse JSON");
        // println!("{:?}", json_data_vk);

        // ! Serialize into Bytes
        let bytes_vk = postcard::to_allocvec(&json_data_vk).unwrap();
        // println!("{:?}", bytes_vk);

        // ! Write bytes to file
        let output_path_vk = "./src/resources/bin/vk.bin";
        fs::write(output_path_vk, bytes_vk).expect("Failed to write binary file");
        // ! Read bytes from file
        let bytes_from_file_vk = fs::read(output_path_vk).unwrap();

        // ! Just a check that it is in right format and it can be deserialized
        let deserialized_value_vk =
            deserializer::deserialize_vk::<E1, E2, EE1, EE2>(&bytes_from_file_vk);

        bytes_from_file_vk
    }

    // ! Helper functions
    fn handle_compressed_snark<E1, E2, EE1, EE2>() -> Vec<u8>
    where
        E1: Engine<Base = <E2 as Engine>::Scalar>,
        E2: Engine<Base = <E1 as Engine>::Scalar>,
        EE1: EvaluationEngineTrait<E1>,
        EE2: EvaluationEngineTrait<E2>,
    {
        let json_path_compressed_snark = "./src/resources/json/compressed_snark.json";
        // ! Read from JSON to String
        let json_string_compressed_snark =
            fs::read_to_string(json_path_compressed_snark).expect("Failed to read JSON file");

        // ! From string into CompressedSTARK
        let json_data_compressed_snark: CompressedSNARK<
            E1,
            E2,
            TrivialCircuit<<E1 as Engine>::Scalar>,
            CubicCircuit<<E2 as Engine>::Scalar>,
            S<E1, EE1>,
            S<E2, EE2>,
        > = serde_json::from_str(&json_string_compressed_snark).expect("Failed to parse JSON");
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
        let deserialized_value_compressed_snark =
            deserializer::deserialize_compressed_snark::<E1, E2, EE1, EE2>(
                &bytes_from_file_compressed_snark,
            );

        bytes_from_file_compressed_snark
    }
}
