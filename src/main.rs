extern crate bitcoin;

use crate::bitcoin::secp256k1::rand::RngCore;

use bitcoin::hashes::Hash;
use bitcoin::hashes::HashEngine;
use bitcoin::network::constants::Network;
use bitcoin::schnorr::PublicKey;
use bitcoin::secp256k1::rand::rngs::OsRng;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::address::Address;
use bitcoin::util::taproot::TapTweakHash;
use bitcoin::util::ecdsa::PrivateKey;

use std::env;

fn main() {

use crate::bitcoin::secp256k1::rand::Rng;
use crate::bitcoin::secp256k1::rand::prelude::SliceRandom;

if bitcoin::secp256k1::rand::random() { // generates a boolean
    print!("char: {:}\n", bitcoin::secp256k1::rand::random::<char>());
    print!("char: {:?}\n", bitcoin::secp256k1::rand::random::<char>());
} else {
    print!("char: {:}\n", bitcoin::secp256k1::rand::random::<char>());
    print!("char: {:?}\n", bitcoin::secp256k1::rand::random::<char>());
}

let mut rng = OsRng::new().unwrap();
//print!("\n\n\n   rng={:?}   \n\n\n",&rng);
let mut b_rng = bitcoin::secp256k1::rand::thread_rng();
let b: f64 = b_rng.gen(); // generates a float between 0 and 1
print!("b={:?}\n",&b);
let y: f64 = rng.gen(); // generates a float between 0 and 1
print!("y={:?}\n",&y);
let mut key = [0u8; 16];
let c = Some(rng.try_fill_bytes(&mut key).unwrap());
print!("c={:?}\n",&c);
//let d = Some(rng.try_fill_bytes(&mut y).unwrap());
//print!("d={:?}\n",&d);
//bitcoin::secp256k1::rand::prelude::ThreadRng::try_fill_bytes(&mut key).unwrap();
//let random_u64 = rng.next_u64().unwrap();
//    let mut rng = OsRng::new().unwrap();
  //  print!("\n\n\n   rng={:?}   \n\n\n",&rng);


let mut nums: Vec<i32> = (1..100).collect();
nums.shuffle(&mut rng);


    let mut args: Vec<String> = env::args().collect();
    let mut prefix: String = "bc1p000".to_string();

    if args.len() == 2 {
        prefix = args[1].to_lowercase();
    }
    if args.len() >= 3 || prefix.len() <= 4 {
        println!("try:\nrust-vanity-gen bc1p000");
        return;
    }
    if prefix.get(0..4) != Some("bc1p") {
        println!("Invalid prefix, must begin with bc1p");
        return;
    }

    const CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let prefix_split: Vec<&str> = prefix.split("1").collect();
    for pc in prefix_split[1].chars() {
        if !CHARSET.contains(pc) {
            println!("Invalid character in prefix");
            return;
        }
    }

    let mut merkle_root: Vec<u8> = Vec::new();
    if args.len() == 3 {
        merkle_root = hex::decode(&args[2]).unwrap();
    }

    let secp = Secp256k1::new();

    let mut rng = OsRng::new().unwrap();
    print!("\n\n\n   rng={:?}   \n\n\n",&rng);

    loop {
        let (internal_seckey, internal_pubkey) = secp.generate_schnorrsig_keypair(&mut rng);

        let mut tweak: Vec<u8> = Vec::new();
        tweak.extend_from_slice(&internal_pubkey.serialize());
        tweak.extend_from_slice(&merkle_root);
        let mut engine = TapTweakHash::engine();
        engine.input(&tweak);
        let tweak_value: [u8; 32] = TapTweakHash::from_engine(engine).into_inner();

        let mut output_seckey = internal_seckey.clone();
        output_seckey.tweak_add_assign(&secp, &tweak_value).unwrap();

        let output_pubkey = PublicKey::from_keypair(&secp, &output_seckey);

        let addr = Address::p2tr(output_pubkey, Network::Bitcoin);

        if addr.to_string().get(0..prefix.len()) == Some(&prefix) {
            let internal_privkey = PrivateKey::from_slice(&internal_seckey.serialize_secret(), Network::Bitcoin).unwrap();
            println!("internal_privkey: {}", internal_privkey.to_wif());
            println!("internal_pubkey: {}", internal_pubkey);
            println!("output_pubkey: {}", output_pubkey);
            println!("Address: {}", addr);
            break;
        }
    }
}
