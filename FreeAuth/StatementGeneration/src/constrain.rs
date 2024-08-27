use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::crh::sha256::constraints::{DigestVar, Sha256Gadget};
use ark_crypto_primitives::snark::SNARK;
use ark_ff::ToConstraintField;
use ark_groth16::Groth16;
use ark_r1cs_std::{bits::uint8::UInt8, eq::EqGadget, R1CSVar};
use ark_relations::ns;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use rand::rngs::OsRng;

const ALPHABET_SIZE: usize = 64;
const URL_SAFE: &[u8; ALPHABET_SIZE] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
// const INVALID_VALUE: u8 = 255;

pub const fn decode_table(alphabet: &[u8]) -> [u8; 256] {
    // Two ways:
    // 1) Map(UInt8<ConstraintF>,UInt8<ConstraintF>);(HashMap will Introduce Multi times Hash Compution, increase the number of constains)
    // 2) Switch(UInt8<ConstraintF>) -> Bytes (Present Implementation)
    let mut decode_table = [0; 256];
    let mut index = 0;
    while index < 64 {
        decode_table[alphabet[index] as usize] = index as u8;
        index += 1;
    }
    decode_table
}

const URLSAFE_TABLE: [u8; 256] = decode_table(URL_SAFE);

pub type ConstraintF = ark_ed_on_bls12_381::Fq;

fn decoded_len_estimate(base64string: &[UInt8<ConstraintF>]) -> usize {
    let encoded_len = base64string.len();
    let rem = encoded_len % 4;
    let res = (encoded_len / 4 + (rem > 0) as usize) * 3;
    res
}
fn decode(
    cs: ConstraintSystemRef<ConstraintF>,
    input: &[UInt8<ConstraintF>],
) -> Result<Vec<UInt8<ConstraintF>>, SynthesisError> {
    let estimate_len = decoded_len_estimate(input);
    let mut u8output = vec![0; estimate_len];
    let input_complete_nonterminal_quads_len = input.len() - input.len() % 4;
    const UNROLLED_INPUT_CHUNK_SIZE: usize = 32;
    const UNROLLED_OUTPUT_CHUNK_SIZE: usize = UNROLLED_INPUT_CHUNK_SIZE / 4 * 3;
    let input_complete_quads_after_unrolled_chunks_len =
        input_complete_nonterminal_quads_len % UNROLLED_INPUT_CHUNK_SIZE;
    let input_unrolled_loop_len =
        input_complete_nonterminal_quads_len - input_complete_quads_after_unrolled_chunks_len;
    for (chunk_index, chunk) in input[..input_unrolled_loop_len]
        .chunks_exact(UNROLLED_INPUT_CHUNK_SIZE)
        .enumerate()
    {
        let input_index = chunk_index * UNROLLED_INPUT_CHUNK_SIZE;
        let chunk_output = &mut u8output[chunk_index * UNROLLED_OUTPUT_CHUNK_SIZE
            ..(chunk_index + 1) * UNROLLED_OUTPUT_CHUNK_SIZE];
        for i in 0..4 {
            let _ =decode_chunk_8(
                &chunk[8 * i..8 * (i + 1)],
                input_index,
                &mut chunk_output[6 * i..6 * (i + 1)],
            );
        }
    }
    let output_unrolled_loop_len = input_unrolled_loop_len / 4 * 3;
    let output_complete_quad_len = input_complete_nonterminal_quads_len / 4 * 3;
    {
        let output_after_unroll = &mut u8output[output_unrolled_loop_len..output_complete_quad_len];
        for (chunk_index, chunk) in input
            [input_unrolled_loop_len..input_complete_nonterminal_quads_len]
            .chunks_exact(4)
            .enumerate()
        {
            let chunk_output = &mut output_after_unroll[chunk_index * 3..chunk_index * 3 + 3];
            let _ =decode_chunk_4(
                chunk,
                input_unrolled_loop_len + chunk_index * 4,
                chunk_output,
            );
        }
    }
    let _ =decode_suffix(
        input,
        input_complete_nonterminal_quads_len,
        &mut u8output,
        output_complete_quad_len,
    );
    let output = UInt8::new_witness_vec(ns!(cs, "decodetoken"), &u8output)?;
    Ok(output)
}

fn decode_chunk_8(
    input: &[UInt8<ConstraintF>],
    _index_at_start_of_input: usize,
    output: &mut [u8],
) -> Result<(), SynthesisError> {
    let mut accum = 0u64;
    for i in 0..8 {
        // let morsel = URLSAFE_TABLE[input[i].value().unwrap() as usize];
        // let value = match input[i].value() {
        //     Ok(value) => value,
        //     Err(err) => return Err(err),
        // };
        // println!("decode_chunk_8_1");
        let morsel = URLSAFE_TABLE[input[i].value()? as usize];
        // println!("decode_chunk_8_1");
        // let morsel = URLSAFE_TABLE[value as usize];
        accum |= u64::from(morsel) << 64 - (i + 1) * 6;
    }
    output[..6].copy_from_slice(&accum.to_be_bytes()[..6]);
    Ok(())
}

fn decode_chunk_4(
    input: &[UInt8<ConstraintF>],
    _index_at_start_of_input: usize,
    output: &mut [u8],
) -> Result<(), SynthesisError> {
    let mut accum = 0u32;
    for i in 0..4 {
        // let morsel = URLSAFE_TABLE[input[i].value().unwrap() as usize];
        // let value = match input[i].value() {
        //     Ok(value) => value,
        //     Err(err) => return Err(err),
        // };
        // let morsel = URLSAFE_TABLE[value as usize];
        let morsel = URLSAFE_TABLE[input[i].value()? as usize];
        // println!("decode_chunk_4");
        accum |= u32::from(morsel) << 32 - (i + 1) * 6;
    }
    output[..3].copy_from_slice(&accum.to_be_bytes()[..3]);
    Ok(())
}

fn decode_suffix(
    input: &[UInt8<ConstraintF>],
    input_index: usize,
    output: &mut [u8],
    output_index: usize,
) -> Result<(), SynthesisError> {
    debug_assert!((input.len() - input_index) <= 4);
    if input.len() == input_index {
        return Ok(());
    }
    let mut morsels_in_leftover = 0;
    let mut morsels = [0_u8; 4];
    for (_, b) in input[input_index..].iter().enumerate() {
        // let morsel = URLSAFE_TABLE[b.value().unwrap() as usize];
        // let value = match b.value() {
        //     Ok(value) => value,
        //     Err(err) => return Err(err),
        // };
        // let morsel = URLSAFE_TABLE[value as usize];
        let morsel = URLSAFE_TABLE[b.value()? as usize];
        // println!("decode_suffix");
        morsels[morsels_in_leftover] = morsel;
        morsels_in_leftover += 1;
    }
    let leftover_num = (u32::from(morsels[0]) << 26)
        | (u32::from(morsels[1]) << 20)
        | (u32::from(morsels[2]) << 14)
        | (u32::from(morsels[3]) << 8);
    output[output_index..output_index+3].copy_from_slice(&leftover_num.to_be_bytes()[..3]);
    Ok(())
}

// Statement Example 1
// Authentication of email domains
struct ParseProofDemo1 {
    // Public input
    pub hashchecker: Vec<u8>,
    // Private witness
    pub primval: Vec<u8>,
    pub salt:Vec<u8>,
    pub email: Vec<u8>,
}

impl ConstraintSynthesizer<ConstraintF> for ParseProofDemo1 {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let hashchecker = UInt8::new_input_vec(ns!(cs, "hashchecker"), &self.hashchecker)?;
        let hashchecker = DigestVar(hashchecker);

        let head = UInt8::constant_vec(b"AUTH PLAIN ");

        let salt= UInt8::new_witness_vec(ns!(cs, "salt"), &self.salt)?;
        let primval = UInt8::new_witness_vec(ns!(cs, "base64value"), &self.primval)?;
        let email = UInt8::new_witness_vec(ns!(cs, "email"), &self.email)?;

        let saltlength = salt.len();
        let headlength = head.len()+saltlength;

        let hash = Sha256Gadget::digest(&primval)?;
        hash.enforce_equal(&hashchecker)?;

        primval[saltlength..headlength].enforce_equal(&head)?;

        
        let output = decode(cs, &primval[headlength..])?;
        let payloadhead = UInt8::constant_vec(&[b'\0']);
        let payloadtail = UInt8::constant_vec(b"@gmail.com\0");
        let headlength = payloadhead.len();
        let taillength = payloadtail.len();
        let emaillength = email.len();
        output[..headlength].enforce_equal(&payloadhead)?;
        output[headlength..headlength + emaillength].enforce_equal(&email)?;
        output[headlength + emaillength..headlength + emaillength + taillength]
            .enforce_equal(&payloadtail)?;
        Ok(())
    }
}

pub fn groth16test1() {
    let email = b"alice".to_vec();
    let hashchecker =
        match hex::decode("05c9e6d518f91d2bd3fb3c6be84f6528151e139e8646c367ac8778b0a55d7050") {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Error decoding hex string: {}", e);
                return;
            }
        };
    let salt =b"AsHd1j24021p6ty9".to_vec();
    let primval = b"AsHd1j24021p6ty9AUTH PLAIN AGFsaWNlQGdtYWlsLmNvbQB0ZXN0dHR0dA===".to_vec();

    let mut os_rng = OsRng;
    let copy_hashchecker = hashchecker.clone();
    println!("========Statement Example 1: Authentication of email domainsAuthentication of email domains=========");
    println!("Creating parameters...");
    let (pk, vk) = {
        let c = ParseProofDemo1 {
            hashchecker: hashchecker.clone(),
            primval: primval.clone(),
            salt:salt.clone(),
            email: email.clone(),
        };
        Groth16::<Bls12_381>::circuit_specific_setup(c, &mut os_rng).unwrap()
    };
    let pvk = Groth16::<Bls12_381>::process_vk(&vk).unwrap();
    println!("Creating proofs...");
    use std::time::{Duration, Instant};
    let start = Instant::now();
    let mut totaltime = Duration::new(0, 0);
    let c = ParseProofDemo1 {
        hashchecker,
        primval,
        salt,
        email,
    };
    let proof = Groth16::<Bls12_381>::prove(&pk, c, &mut os_rng).unwrap();
    assert!(Groth16::<Bls12_381>::verify_with_processed_vk(
        &pvk,
        &[copy_hashchecker.to_field_elements().unwrap(),].concat(),
        &proof
    )
    .unwrap());
    totaltime += start.elapsed();
    println!(
        "{:?} seconds",
        totaltime.subsec_nanos() as f64 / 1_000_000_000f64 + (totaltime.as_secs() as f64)
    )
}



// statement example 2
// Authentication of email addresses and generation of identifiers
struct ParseProofDemo2 {
    // Public input
    pub hashchecker1: Vec<u8>,
    pub hashchecker2: Vec<u8>,
    // Private witness
    pub primval: Vec<u8>,
    pub salt :Vec<u8>,
    pub random :Vec<u8>,
    pub email: Vec<u8>,
}

impl ConstraintSynthesizer<ConstraintF> for ParseProofDemo2 {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let hashchecker1 = UInt8::new_input_vec(ns!(cs, "hashchecker1"), &self.hashchecker1)?;
        let hashchecker1 = DigestVar(hashchecker1);

        let hashchecker2 = UInt8::new_input_vec(ns!(cs, "hashchecker2"), &self.hashchecker2)?;
        let hashchecker2 = DigestVar(hashchecker2);

        let head = UInt8::constant_vec(b"AUTH PLAIN ");

        let salt= UInt8::new_witness_vec(ns!(cs, "salt"), &self.salt)?;

        let random=UInt8::new_witness_vec(ns!(cs,"random"),&self.random)?;

        let primval = UInt8::new_witness_vec(ns!(cs, "base64value"), &self.primval)?;
        let email = UInt8::new_witness_vec(ns!(cs, "email"), &self.email)?;

        let saltlength = salt.len();

        let headlength = head.len()+saltlength;

        let hash = Sha256Gadget::digest(&primval)?;
        hash.enforce_equal(&hashchecker1)?;
        primval[saltlength..headlength].enforce_equal(&head)?;

        let output = decode(cs, &primval[headlength..])?;
        let payloadhead = UInt8::constant_vec(&[b'\0']);
        let payloadtail = UInt8::constant_vec(b"\0");
        let headlength = payloadhead.len();
        let taillength = payloadtail.len();
        let emaillength = email.len();
        output[..headlength].enforce_equal(&payloadhead)?;
        output[headlength..headlength + emaillength].enforce_equal(&email)?;
        output[headlength + emaillength..headlength + emaillength + taillength]
            .enforce_equal(&payloadtail)?;
        
        random[..emaillength].enforce_equal(&email)?;
        let hash2 = Sha256Gadget::digest(&random)?;
        
        hash2.enforce_equal(&hashchecker2)?;
        Ok(())
    }
}

pub fn groth16test2() {
    let email = b"alice@gmail.com".to_vec();
    let random =b"alice@gmail.comAsHd1j24021p6ty9AsHd1j24021p6ty9AsHd1j24021p6ty9".to_vec();
    let hashchecker1 =
        match hex::decode("05c9e6d518f91d2bd3fb3c6be84f6528151e139e8646c367ac8778b0a55d7050") {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Error decoding hex string: {}", e);
                return;
            }
        };
    let hashchecker2 =
        match hex::decode("6f4135e86446337c7f69e551cf247b0c7d94f9011e43b6a87eec2e3c6537f07f") {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Error decoding hex string: {}", e);
                return;
            }
        };

    let salt =b"AsHd1j24021p6ty9".to_vec();
    let primval = b"AsHd1j24021p6ty9AUTH PLAIN AGFsaWNlQGdtYWlsLmNvbQB0ZXN0dHR0dA===".to_vec();

    let mut os_rng = OsRng;
    let copy_hashchecker1 = hashchecker1.clone();
    let copy_hashchecker2 = hashchecker2.clone();
    println!("========Statement Example 2: Authentication of email addresses and generation of identifiers=========");
    println!("Creating parameters...");
    let (pk, vk) = {
        let c = ParseProofDemo2 {
            hashchecker1: hashchecker1.clone(),
            hashchecker2: hashchecker2.clone(),
            primval: primval.clone(),
            salt:salt.clone(),
            random:random.clone(),
            email: email.clone(),
        };
        Groth16::<Bls12_381>::circuit_specific_setup(c, &mut os_rng).unwrap()
    };

    let pvk = Groth16::<Bls12_381>::process_vk(&vk).unwrap();
    println!("Creating proofs...");
    use std::time::{Duration, Instant};
    let start = Instant::now();
    let mut totaltime = Duration::new(0, 0);
    let c = ParseProofDemo2 {
        hashchecker1,
        hashchecker2,
        primval,
        salt,
        random,
        email,
    };
    let proof = Groth16::<Bls12_381>::prove(&pk, c, &mut os_rng).unwrap();
    assert!(Groth16::<Bls12_381>::verify_with_processed_vk(
        &pvk,
        &[copy_hashchecker1.to_field_elements().unwrap(),copy_hashchecker2.to_field_elements().unwrap(),].concat(),
        &proof
    )
    .unwrap());
    totaltime += start.elapsed();
    println!(
        "{:?} seconds",
        totaltime.subsec_nanos() as f64 / 1_000_000_000f64 + (totaltime.as_secs() as f64)
    )
}

// statement example 3
// Authentication of email address
struct ParseProofDemo3 {
    // Public input
    pub hashchecker: Vec<u8>,
    // Private witness
    pub primval: Vec<u8>,
    pub salt:Vec<u8>,
    // pub email: Vec<u8>,
}

impl ConstraintSynthesizer<ConstraintF> for ParseProofDemo3 {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
       
        let hashchecker = UInt8::new_input_vec(ns!(cs, "hashchecker"), &self.hashchecker)?;
        let hashchecker = DigestVar(hashchecker);

        
        let head = UInt8::constant_vec(b"AUTH PLAIN ");

        let salt= UInt8::new_witness_vec(ns!(cs, "salt"), &self.salt)?;
        let primval = UInt8::new_witness_vec(ns!(cs, "base64value"), &self.primval)?;
        // let email = UInt8::new_witness_vec(ns!(cs, "email"), &self.email)?;

        let saltlength = salt.len();
        let headlength = head.len()+saltlength;

        let hash = Sha256Gadget::digest(&primval)?;
        hash.enforce_equal(&hashchecker)?;

        primval[saltlength..headlength].enforce_equal(&head)?;

        let output = decode(cs, &primval[headlength..])?;
        let payloadhead = UInt8::constant_vec(&[b'\0']);
        let payloadtail = UInt8::constant_vec(b"alice@gmail.com\0");
        let headlength = payloadhead.len();
        let taillength = payloadtail.len();
        output[..headlength].enforce_equal(&payloadhead)?;
        output[headlength..headlength + taillength]
            .enforce_equal(&payloadtail)?;
        Ok(())
    }
}

pub fn groth16test3() {

    let hashchecker =
        match hex::decode("05c9e6d518f91d2bd3fb3c6be84f6528151e139e8646c367ac8778b0a55d7050") {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Error decoding hex string: {}", e);
                return;
            }
        };
    let salt =b"AsHd1j24021p6ty9".to_vec();
    let primval = b"AsHd1j24021p6ty9AUTH PLAIN AGFsaWNlQGdtYWlsLmNvbQB0ZXN0dHR0dA===".to_vec();

    let mut os_rng = OsRng;
    let copy_hashchecker = hashchecker.clone();
    println!("========Statement Example 3: Authentication of email address=========");

    println!("Creating parameters...");
    let (pk, vk) = {
        let c = ParseProofDemo3 {
            hashchecker: hashchecker.clone(),
            primval: primval.clone(),
            salt:salt.clone(),
        };
        Groth16::<Bls12_381>::circuit_specific_setup(c, &mut os_rng).unwrap()
    };
    let pvk = Groth16::<Bls12_381>::process_vk(&vk).unwrap();
    println!("Creating proofs...");
    use std::time::{Duration, Instant};
    let start = Instant::now();
    let mut totaltime = Duration::new(0, 0);
    let c = ParseProofDemo3 {
        hashchecker,
        primval,
        salt,
        // email,
    };
    let proof = Groth16::<Bls12_381>::prove(&pk, c, &mut os_rng).unwrap();
    assert!(Groth16::<Bls12_381>::verify_with_processed_vk(
        &pvk,
        &[copy_hashchecker.to_field_elements().unwrap(),].concat(),
        &proof
    )
    .unwrap());
    totaltime += start.elapsed();
    println!(
        "{:?} seconds",
        totaltime.subsec_nanos() as f64 / 1_000_000_000f64 + (totaltime.as_secs() as f64)
    )
}