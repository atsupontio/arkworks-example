
use ark_bls12_381::{Fr, Bls12_381};

use ark_r1cs_std::prelude::*;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Field}; 
use ark_r1cs_std::{alloc::AllocVar};
use ark_r1cs_std::eq::EqGadget;

use ark_crypto_primitives::crh::injective_map::constraints::{
    PedersenCRHCompressorGadget, TECompressorGadget, 
};
use ark_crypto_primitives::crh::constraints::{TwoToOneCRHGadget};
use ark_crypto_primitives::crh::{
    injective_map::{PedersenCRHCompressor, TECompressor},
    /*pedersen::constraints::CRHGadget,*/
    pedersen, TwoToOneCRH
};
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective};

use crate::encode::encode_hex; // import Groth16 library

// pub type TwoToOneHash = PedersenCRHCompressor<JubJub, EdwardsVar, Window>;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TwoToOneWindow;

// `WINDOW_SIZE * NUM_WINDOWS` = 2 * 256 bits = enough for hashing two outputs.
// impl pedersen::Window for TwoToOneWindow {
//     const WINDOW_SIZE: usize = 4;
//     const NUM_WINDOWS: usize = 128;
// }

impl pedersen::Window for TwoToOneWindow {
    const WINDOW_SIZE: usize = 8;
    const NUM_WINDOWS: usize = 128;
}

// pub type PedeHash = PedersenCRHCompressor<JubJub, TECompressor, Window>;

pub type TwoToOneHashGadget = PedersenCRHCompressorGadget<
    EdwardsProjective,
    TECompressor,
    TwoToOneWindow,
    EdwardsVar,
    TECompressorGadget,
>;

pub type TwoToOneHashParamsVar =
    <TwoToOneHashGadget as TwoToOneCRHGadget<TwoToOneHash, ConstraintF>>::ParametersVar;
pub type ConstraintF = ark_ed_on_bls12_381::Fq;

pub type TwoToOneHash = PedersenCRHCompressor<EdwardsProjective, TECompressor, TwoToOneWindow>;

/// The R1CS equivalent of the the Merkle tree root.
pub type ImageVar = <TwoToOneHashGadget as TwoToOneCRHGadget<TwoToOneHash, ConstraintF>>::OutputVar;

pub type Image = <TwoToOneHash as TwoToOneCRH>::Output;


#[allow(clippy::upper_case_acronyms)]
#[derive(Clone)]
pub struct HashDemo {
    pub left: Vec<u8>,
    pub right: Vec<u8>,
    pub two_to_one_crh_params: <TwoToOneHash as TwoToOneCRH>::Parameters,
    pub image: Image,
}

impl ConstraintSynthesizer<Fr> for HashDemo { 
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {

        let image = ImageVar::new_input(ark_relations::ns!(cs, "image_var"), || Ok(&self.image))?;

        let two_to_one_crh_params =
        TwoToOneHashParamsVar::new_constant(ark_relations::ns!(cs, "parameters"), &self.two_to_one_crh_params)?;

        let mut left_bytes = vec![];
        for byte in self.left.iter() {
            left_bytes.push(UInt8::new_witness(ark_relations::ns!(cs, "left preimage"), || Ok(byte)).unwrap());
        }
        let mut right_bytes = vec![];
        for byte in self.right.iter() {
            right_bytes.push(UInt8::new_witness(ark_relations::ns!(cs, "right preimage"), || Ok(byte)).unwrap());
        }

        let hash_result_var = TwoToOneHashGadget::evaluate(&two_to_one_crh_params, &left_bytes, &right_bytes).unwrap();

        // let hash_result = hash_result_var.value().unwrap();
        // let hash_result = FpVar::<Fr>::new_witness(
        //     ark_relations::ns!(cs, "new witness x^2"), || Ok(hash_result_var.value())
        // ).expect("create new witness");
        // let image = image.value().unwrap();
        // image.enforce_equal(&hash_result_var.value().unwrap());
        hash_result_var.enforce_equal(&image)?;

        Ok(())
    }
}

// map i64 to a finite field Fp256
fn to_fq(x: i64) -> Fr {
    // get the positive value of x
    let val:u64 = i64::unsigned_abs(x); 
    // map integer to Fp256
    let mut fq: Fr = val.into();  
    if x< 0 { 
        // let modulus = ark_bls12_381::FrParameters::MODULUS;
        // println!("{:#?}", modu);
        // if x is negative, we should return the inverse value
        fq = - fq;   // neg_fq = modulus - fq
    }  
    fq
}



#[test]
fn test_cube_proof(){
    use ark_std::rand::{rngs::StdRng, SeedableRng, Rng};
    use ark_groth16::*;
    use arkworks_native_gadgets::{to_field_elements, from_field_elements};
    use ark_serialize::*;
    //use ark_ec::;
    use crate::encode;
    use crate::encode_hex;

    let id = "5FLSigC9HGRKVhB9FiEo4Y3koPsNmBmLJbpXg2mp1hXcS59Y";
    let secret = "12345678";
    let nonce = "afe387d2";
    let name = "koyamaatsuki";
    let birth = "20000510";

    let new_id = base58::FromBase58::from_base58(id).unwrap();
    let new_id2 = encode_hex::encode_hex(new_id.as_slice());
    println!("new_id: {:?}", new_id2);
    let mut id_bytes = hex::decode(&new_id2).unwrap();
    println!("id_bytes: {:?}", id_bytes);

    let mut secret_bytes = hex::decode(&secret).unwrap();
    println!("secret: {:?}", secret_bytes);

    let mut nonce_bytes = hex::decode(&nonce).unwrap();
    println!("nonce:{:?}", nonce_bytes);

    let new_name = base58::FromBase58::from_base58(name).unwrap();
    let new_name2 = encode_hex::encode_hex(new_name.as_slice());
    println!("new_name: {:?}", new_id2);
    let mut name_bytes = hex::decode(&new_name2).unwrap();
    println!("name_bytes: {:?}", name_bytes);

    let mut birth_bytes = hex::decode(&birth).unwrap();
    println!("secret: {:?}", birth_bytes);

    let mut rng = StdRng::seed_from_u64(0u64);

    //let parameters = TestTwoToOneCRH::setup(rng).unwrap();

    let params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

    id_bytes.append(&mut secret_bytes);
    id_bytes.append(&mut nonce_bytes);
    id_bytes.append(&mut name_bytes);
    id_bytes.append(&mut birth_bytes);

    let mut right_half = Vec::new();

    if id_bytes.len() % 2 == 0 {
        let len = id_bytes.len() / 2;
        right_half = id_bytes.split_off(len);
    } else {
        id_bytes.push(000);
        let len = id_bytes.len() / 2;
        right_half = id_bytes.split_off(len);
    }

    let left = id_bytes;
    let right = right_half;

    let primitive_result = <TwoToOneHash as TwoToOneCRH>::evaluate(&params, left.as_slice(), right.as_slice()).unwrap();
    let mut result_vec = Vec::new();
    primitive_result.serialize(&mut result_vec).unwrap();
    let hex_result = encode_hex::encode_hex(&result_vec);
    println!("result: {:?}", hex_result);
    let circuit = HashDemo {
        left,
        right,
        two_to_one_crh_params: params,
        image: primitive_result,
    };

    let mut statement = Vec::new();
    statement.push(primitive_result);
    // let public_input = from_field_elements(&statement).unwrap();
    // println!("public_input: {:?}", public_input);

    let param = generate_random_parameters::<Bls12_381, _, _>(circuit.clone(), &mut rng).unwrap();
    // let mut vkey_vec = Vec::new();
    // param.vk.serialize(&mut vkey_vec).unwrap();
    // println!("vkey_vec: {:?}", vkey_vec);

    let proof = create_random_proof(circuit.clone(), &param, &mut rng).unwrap();
    // let mut proof_vec = Vec::new();
    // proof.serialize(&mut proof_vec).unwrap();
    // println!("proof_vec: {:?}", proof_vec);


    let pvk = prepare_verifying_key(&param.vk);


    // encode::encode_parameters(proof_vec, vkey_vec, public_input);

    let result = verify_proof(&pvk, &proof, &statement).unwrap();
    println!("verify result is {:?}", result);

}
