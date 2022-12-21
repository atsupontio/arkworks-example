
use ark_bls12_381::{Bls12_381, Fr};
use ark_r1cs_std::prelude::FieldVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError}; 
use ark_r1cs_std::{fields::fp::FpVar, alloc::AllocVar};
use ark_r1cs_std::eq::EqGadget;


// proving that I know x such that x^3 + x + 5 == 35
// Generalized: x^3 + x + 5 == out
#[allow(clippy::upper_case_acronyms)]
#[derive(Clone)]
pub struct CubeDemo {
    pub x: Fr,
}

impl ConstraintSynthesizer<Fr> for CubeDemo { 
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {

        // x is the witness which should be hidden
        let x_val = self.x;
        let x_witness = FpVar::<Fr>::new_witness(
            ark_relations::ns!(cs, "new witness x"), || Ok(self.x)
        ).expect("create new witness"); 

        let tmp_square = x_val * x_val;
        let square_witness = FpVar::<Fr>::new_witness(
            ark_relations::ns!(cs, "new witness x^2"), || Ok(tmp_square)
        ).expect("create new witness");

        x_witness.square_equals(&square_witness)?;

       let tmp_cube = tmp_square * x_val;
       let cube_witness = FpVar::<Fr>::new_witness(
        ark_relations::ns!(cs, "new witness x^3"), || Ok(tmp_cube)
        ).expect("create new witness");

        square_witness.mul_equals(&x_witness, &cube_witness)?;

        let tmp_out = tmp_cube + x_val + Fr::from(5u32);
        let out = FpVar::<Fr>::new_input(
            ark_relations::ns!(cs, "new witness x^3 + x"), || Ok(tmp_out)
        ).expect("create new witness");

        out.enforce_equal(&(cube_witness + x_witness + (Fr::from(5u32))))?;

        Ok(())
    }
}


#[test]
fn test_cube_proof(){
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use ark_groth16::*;
    use arkworks_native_gadgets::{to_field_elements, from_field_elements};
    use ark_serialize::*;

    let mut rng = StdRng::seed_from_u64(0u64);

    let x = Fr::from(3);

    let circuit = CubeDemo {
        x: x,
    };

    let mut statement = Vec::new();
    statement.push(Fr::from(35));
    let public_input = from_field_elements(&statement).unwrap();
    // println!("public_input: {:?}", public_input);

    let param = generate_random_parameters::<Bls12_381, _, _>(circuit.clone(), &mut rng).unwrap();
    let mut vkey_vec = Vec::new();
    param.vk.serialize(&mut vkey_vec).unwrap();
    // println!("vkey_vec: {:?}", vkey_vec);

    let proof = create_random_proof(circuit.clone(), &param, &mut rng).unwrap();
    let mut proof_vec = Vec::new();
    proof.serialize(&mut proof_vec).unwrap();
    // println!("proof_vec: {:?}", proof_vec);


    let pvk = prepare_verifying_key(&param.vk);

    let result = verify_proof(&pvk, &proof, &statement).unwrap();
    println!("verify result is {:?}", result);

}

