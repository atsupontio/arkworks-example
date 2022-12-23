
use ark_bls12_381::{Fr, Bls12_381};

use ark_r1cs_std::{prelude::*, Assignment};
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

use ark_serialize::*;
use crate::encode_hex;

// use crate::encode::encode_hex; // import Groth16 library

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
    pub id: Vec<Option<u8>>,
    pub secret: Vec<Option<u8>>,
    pub nonce: Vec<Option<u8>>,
    pub hashed_name_birth: Vec<Option<u8>>,
    pub two_to_one_crh_params: <TwoToOneHash as TwoToOneCRH>::Parameters,
    pub image: Option<Image>,
}

const NUM_ID: usize = 40; // 35
const NUM_SECRET: usize = 6; // 4
const NUM_NONCR: usize = 6; // 4
const NUM_NAMR_BIRTH: usize = 40; // 32
const NUM_HASH: usize = 92;

use ark_r1cs_std::prelude::AllocationMode::Input;

impl ConstraintSynthesizer<Fr> for HashDemo { 
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {

        let image = ImageVar::new_input(ark_relations::ns!(cs, "image_var"), || self.image.ok_or(SynthesisError::AssignmentMissing))?;

        let two_to_one_crh_params =
        TwoToOneHashParamsVar::new_constant(ark_relations::ns!(cs, "parameters"), &self.two_to_one_crh_params)?;


        let mut left_bytes = vec![];
        for byte in 0..NUM_ID {
            left_bytes.push(UInt8::new_input(ark_relations::ns!(cs, "left preimage"), || self.id[byte].ok_or(SynthesisError::AssignmentMissing)).unwrap());
        }
        for byte in 0..NUM_SECRET {
            left_bytes.push(UInt8::new_witness(ark_relations::ns!(cs, "left preimage"), || self.secret[byte].ok_or(SynthesisError::AssignmentMissing)).unwrap());
        }
        let mut right_bytes = vec![];
        for byte in 0..NUM_NONCR {
            right_bytes.push(UInt8::new_witness(ark_relations::ns!(cs, "left preimage"), || self.nonce[byte].ok_or(SynthesisError::AssignmentMissing)).unwrap());
        }
        for byte in 0..NUM_NAMR_BIRTH {
            right_bytes.push(UInt8::new_input(ark_relations::ns!(cs, "left preimage"), || self.hashed_name_birth[byte].ok_or(SynthesisError::AssignmentMissing)).unwrap());
        }

        let hash_result_var = TwoToOneHashGadget::evaluate(&two_to_one_crh_params, &left_bytes, &right_bytes).unwrap();

        hash_result_var.enforce_equal(&image)?;

        Ok(())
    }
}



fn create_input(id: &str, secret: &str, nonce: &str, name: &str, birth: &str) -> (Vec<Option<u8>>, Vec<Option<u8>>, Vec<Option<u8>>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    // id
    // base58 decode id
    let new_id = base58::FromBase58::from_base58(id).unwrap();
    let new_id2 = encode_hex::encode_hex(new_id.as_slice());
    println!("new_id: {:?}", new_id2);
    // byte
    let id_bytes = hex::decode(&new_id2).unwrap();
    // option byte(0 padding)
    let id_option_bytes = encode_hex::hexdump_option(&id_bytes, NUM_ID);
    println!("id_bytes: {:?}", &id_bytes);
    // byte(0 padding)
    let id_bytes_fix = encode_hex::hexdump(&id_bytes, NUM_ID);

    let secret_bytes = hex::decode(&secret).unwrap();
    println!("secret: {:?}", secret_bytes);
    let secret_option_bytes = encode_hex::hexdump_option(&secret_bytes, NUM_SECRET);
    let secret_bytes_fix = encode_hex::hexdump(&secret_bytes, NUM_SECRET);

    let nonce_bytes = hex::decode(&nonce).unwrap();
    println!("nonce:{:?}", nonce_bytes);
    let nonce_option_bytes = encode_hex::hexdump_option(&nonce_bytes, NUM_NONCR);
    let nonce_bytes_fix = encode_hex::hexdump(&nonce_bytes, NUM_NONCR);

    let new_name = base58::FromBase58::from_base58(name).unwrap();
    let new_name2 = encode_hex::encode_hex(new_name.as_slice());
    println!("new_name: {:?}", new_name2);
    let name_bytes = hex::decode(&new_name2).unwrap();
    println!("name_bytes: {:?}", name_bytes);


    let birth_bytes = hex::decode(&birth).unwrap();
    println!("secret: {:?}", birth_bytes);


    return (id_option_bytes, secret_option_bytes, nonce_option_bytes, id_bytes_fix, secret_bytes_fix, nonce_bytes_fix, name_bytes, birth_bytes);
}

fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::new();
    for byte in bytes {
        for i in 0..8 {
            bits.push((byte >> i) & 1 == 1);
        }
    }
    bits
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

    let mut rng = StdRng::seed_from_u64(0u64);

    //let parameters = TestTwoToOneCRH::setup(rng).unwrap();

    // params to create hash
    let params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

    // input
    let id = "5FLSigC9HGRKVhB9FiEo4Y3koPsNmBmLJbpXg2mp1hXcS59Y";
    let secret = "12345678";
    let nonce = "afe387d2";
    let name = "koyamaatsuki";
    let birth = "20000510";

    // make from str input to byte or option byte
    let (id_option_bytes, secret_option_bytes, mut nonce_option_bytes, mut id_bytes, mut secret_bytes, mut nonce_bytes,  mut name_bytes, mut birth_bytes) = create_input(id, secret, nonce, name, birth);

    // byte array to create hash
    name_bytes.append(&mut birth_bytes);

    // create name and birthday hash
    let mut pub_right = Vec::new();

    if name_bytes.len() % 2 == 0 {
        let len = name_bytes.len() / 2;
        pub_right = name_bytes.split_off(len);
    } else {
        name_bytes.push(000);
        let len = name_bytes.len() / 2;
        pub_right = name_bytes.split_off(len);
    }

    let hashed_name_birth = <TwoToOneHash as TwoToOneCRH>::evaluate(&params, &name_bytes.as_slice(), &pub_right.as_slice()).unwrap();
    let mut result_vec = Vec::new();
    hashed_name_birth.serialize(&mut result_vec).unwrap();
    let mut result2 = result_vec.clone();
    // name and birthday hash by option byte array(0 padding)
    let result_bytes_option = encode_hex::hexdump_option(&result2, NUM_NAMR_BIRTH);// size 40
    // name and birthday hash byte array(0 padding)
    let result_bytes = encode_hex::hexdump(&result2, NUM_NAMR_BIRTH);// size 40

    let mut preimage = id_bytes.clone(); // size 40

    // create byte array for hash
    preimage.append(&mut secret_bytes); // size 40 + 6
    preimage.append(&mut nonce_bytes); // size 46 + 6
    preimage.append(&mut result2); // size 52 + 40

    let mut right_half = Vec::new();

    let len = preimage.len() / 2;
    right_half = preimage.split_off(len);

    let left = preimage;
    let right = right_half;

    // hash result
    let primitive_result = <TwoToOneHash as TwoToOneCRH>::evaluate(&params, left.as_slice(), right.as_slice()).unwrap();
    let mut image_vec = Vec::new();
    primitive_result.serialize(&mut image_vec).unwrap();
    // hex hash result
    let hex_result = encode_hex::encode_hex(&image_vec);
    println!("result: {:?}", hex_result);


    let pre_circuit = HashDemo {
        id: vec![None; NUM_ID],
        secret: vec![None; NUM_SECRET],
        nonce: vec![None; NUM_NONCR],
        hashed_name_birth: vec![None; NUM_NAMR_BIRTH],
        two_to_one_crh_params: params.clone(),
        image: None,
    };

    // public input
    let mut statement = Vec::new();

    let id_bits = bytes_to_bits(&id_bytes);
    let name_birth_bits = bytes_to_bits(&result_bytes);

    statement.push(primitive_result);
    for i in 0..NUM_ID * 8{
        statement.push(Fr::from(id_bits[i]))
    }
    for i in 0..NUM_NAMR_BIRTH * 8{
        statement.push(Fr::from(name_birth_bits[i]))
    }
    
    // let public_input = from_field_elements(&statement).unwrap();
    // println!("public_input: {:?}", public_input);

    // parameters to create proof and vk
    let param = generate_random_parameters::<Bls12_381, _, _>(pre_circuit.clone(), &mut rng).unwrap();
    // let mut vkey_vec = Vec::new();
    // param.vk.serialize(&mut vkey_vec).unwrap();
    // println!("vkey_vec: {:?}", vkey_vec);

    let circuit = HashDemo {
        id: id_option_bytes,
        secret: secret_option_bytes,
        nonce: nonce_option_bytes,
        hashed_name_birth: result_bytes_option,
        two_to_one_crh_params: params.clone(),
        image: Some(primitive_result),
    };


    // proof
    let proof = create_random_proof(circuit.clone(), &param, &mut rng).unwrap();
    // let mut proof_vec = Vec::new();
    // proof.serialize(&mut proof_vec).unwrap();
    // println!("proof_vec: {:?}", proof_vec);

    // verification key
    let pvk = prepare_verifying_key(&param.vk);
    println!("ic: {:?}", pvk.vk.gamma_abc_g1.len());
    println!("statement len {:?}", statement.len());


    // encode::encode_parameters(proof_vec, vkey_vec, public_input);

    let result = verify_proof(&pvk, &proof, &statement).unwrap();
    println!("verify result1 is {:?}", result);



 /* ----------------------------------------------------------------------------- */


    // let id2 = "5FLSigC9HGRKVhB9FiEo4Y3koPsNmBmLJbpXg2mp1hXcS59Y";
    // let secret2 = "12875678";
    // let nonce2 = "afe387d2";
    // let name2 = "koyamaatsuki";
    // let birth2 = "20044510";

    // let (id_option_bytes2, mut secret_option_bytes2, mut nonce_option_bytes2, mut id_bytes2, mut secret_bytes2, mut nonce_bytes2,  mut name_bytes2, mut birth_bytes2) = create_input(id2, secret2, nonce2, name2, birth2);


    // name_bytes2.append(&mut birth_bytes2);

    // let mut pub_right2 = Vec::new();

    // if name_bytes2.len() % 2 == 0 {
    //     let len = name_bytes2.len() / 2;
    //     pub_right2 = name_bytes2.split_off(len);
    // } else {
    //     name_bytes2.push(000);
    //     let len = name_bytes2.len() / 2;
    //     pub_right2 = name_bytes2.split_off(len);
    // }


    // let hashed_name_birth2 = <TwoToOneHash as TwoToOneCRH>::evaluate(&params, &name_bytes2.as_slice(), &pub_right2.as_slice()).unwrap();
    // let mut result_vec2 = Vec::new();
    // hashed_name_birth2.serialize(&mut result_vec2).unwrap();
    // let mut result22 = result_vec2.clone();
    // let result_bytes2 = encode_hex::hexdump_option(&result22, NUM_NAMR_BIRTH);

    // let mut preimage2 = id_bytes2.clone();

    // preimage2.append(&mut secret_bytes2);
    // preimage2.append(&mut nonce_bytes2);
    // preimage2.append(&mut result22);

    // let mut right_half2 = Vec::new();

    // let len = preimage2.len() / 2;
    // right_half2 = preimage2.split_off(len);

    // let left2 = preimage2;
    // let right2 = right_half2;

    // let primitive_result2 = <TwoToOneHash as TwoToOneCRH>::evaluate(&params, left2.as_slice(), right2.as_slice()).unwrap();
    // let mut image_vec2 = Vec::new();
    // primitive_result2.serialize(&mut image_vec2).unwrap();
    // let hex_result2 = encode_hex::encode_hex(&image_vec2);
    // println!("result: {:?}", hex_result2);

    // let mut statement2 = Vec::new();
    // statement2.push(primitive_result2);


    // let circuit2 = HashDemo {
    //     id: id_option_bytes2,
    //     secret: secret_option_bytes2,
    //     nonce: nonce_option_bytes2,
    //     hashed_name_birth: result_bytes2,
    //     two_to_one_crh_params: params.clone(),
    //     image: Some(primitive_result2),
    // };

    // let proof2 = create_random_proof(circuit2.clone(), &param, &mut rng).unwrap();
    // // let mut proof_vec = Vec::new();
    // // proof.serialize(&mut proof_vec).unwrap();
    // // println!("proof_vec: {:?}", proof_vec);


    // let pvk2 = prepare_verifying_key(&param.vk);


    // // encode::encode_parameters(proof_vec, vkey_vec, public_input);

    // let result2 = verify_proof(&pvk2, &proof2, &statement2).unwrap();
    // println!("verify result2 is {:?}", result2);
}