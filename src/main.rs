extern crate bitcoin;

use crate::bitcoin::secp256k1::rand::prelude::SliceRandom;
use crate::bitcoin::secp256k1::rand::Rng;
use crate::bitcoin::secp256k1::rand::RngCore;

use bitcoin::hashes::Hash;
use bitcoin::hashes::HashEngine;
use bitcoin::network::constants::Network;
use bitcoin::schnorr::PublicKey;
use bitcoin::secp256k1::rand::rngs::OsRng;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::address::Address;
use bitcoin::util::ecdsa::PrivateKey;
use bitcoin::util::taproot::TapTweakHash;

use std::env;

fn main() {
    if bitcoin::secp256k1::rand::random() {
        // generates a boolean
        print!(
            "true:char: {:}\n",
            bitcoin::secp256k1::rand::random::<char>()
        );
        print!(
            "true:char: {:?}\n",
            bitcoin::secp256k1::rand::random::<char>()
        );
    } else {
        print!(
            "false:char: {:}\n",
            bitcoin::secp256k1::rand::random::<char>()
        );
        print!(
            "false:char: {:?}\n",
            bitcoin::secp256k1::rand::random::<char>()
        );
    }

    let mut rng = OsRng::new().unwrap();

    //print!("\n\n\n   rng={:?}   \n\n\n",&rng);
    let y: f64 = rng.gen(); // generates a float between 0 and 1
    print!("y={:?}\n", &y);

    let mut key = [1u8; 16];
    rng.try_fill_bytes(&mut key).unwrap();

    let c: f64 = rng.gen(); // generates a float between 0 and 1
    print!("c={:?}\n", &c);

    let d = rng.next_u64();
    print!("d={:?}\n", &d);

    let mut nums: Vec<i32> = (0..255).collect();
    print!("nums={:?}\n", &nums);
    nums.shuffle(&mut rng);
    print!("nums={:?}\n", &nums);
    //std::process::exit(0);


//
    let mut b_rng = bitcoin::secp256k1::rand::thread_rng();
    let b: f64 = b_rng.gen(); // generates a float between 0 and 1
    print!("b={:?}\n", &b);

    let mut args: Vec<String> = env::args().collect();
    let mut prefix: String = "bc1p000".to_string();

    if args.len() == 2 {
        prefix = args[1].to_lowercase();
    }
    if prefix.len() <= 4 {
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
            println!("Invalid character in prefix.\nUse:\n{}", CHARSET);
            return;
        }
    }

    let mut merkle_root: Vec<u8> = Vec::new();
    if args.len() == 3 {
        merkle_root = hex::decode(&args[2]).unwrap();
        print!("merkle_root={:?}\n",merkle_root);
    }

    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    let secp = bitcoin::secp256k1::Secp256k1::new();
    use std::str::FromStr;
    use secp256k1::Keypair;
    let secret_key = secp256k1::SecretKey::from_str("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
    //let key = Keypair::from_secret_key(&secp, &key_0);

    loop {
        let (internal_seckey, internal_pubkey) = secp.generate_schnorrsig_keypair(&mut rng);
        print!("internal_seckey={:?}\n",internal_seckey);
        print!("internal_pubkey={:?}\n",internal_pubkey);

        let mut tweak: Vec<u8> = Vec::new();
        print!("tweak={:?}\n",tweak);
        tweak.extend_from_slice(&internal_pubkey.serialize());
        print!("tweak.extend_from_slice={:?}\n",tweak);
        tweak.extend_from_slice(&merkle_root);
        print!("tweak.extend_from_slice={:?}\n",tweak);
        let mut engine = TapTweakHash::engine();
        engine.input(&tweak);
        let tweak_value: [u8; 32] = TapTweakHash::from_engine(engine).into_inner();
        print!("tweak.value={:?}\n",tweak_value);

        let mut output_seckey = internal_seckey.clone();
        output_seckey.tweak_add_assign(&secp, &tweak_value).unwrap();

        let output_pubkey = PublicKey::from_keypair(&secp, &output_seckey);

        let addr = Address::p2tr(output_pubkey, Network::Bitcoin);

        if addr.to_string().get(0..prefix.len()) == Some(&prefix) {
            let internal_privkey =
                PrivateKey::from_slice(&internal_seckey.serialize_secret(), Network::Bitcoin)
                    .unwrap();
            println!("internal_privkey: {}", internal_privkey.to_wif());
            println!("internal_pubkey: {}", internal_pubkey);
            println!("output_pubkey: {}", output_pubkey);
            println!("Address: {}", addr);
            break;
        }
    }
}
