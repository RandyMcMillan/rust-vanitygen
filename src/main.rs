extern crate bitcoin;

use crate::bitcoin::secp256k1::rand::prelude::SliceRandom;
use crate::bitcoin::secp256k1::rand::Rng;
use crate::bitcoin::secp256k1::rand::RngCore;

use bitcoin::hashes::Hash;
use bitcoin::hashes::HashEngine;
use bitcoin::network::constants::Network;
use bitcoin::schnorr::PublicKey;
use bitcoin::secp256k1::rand::rngs::OsRng;
use bitcoin::util::address::Address;
use bitcoin::util::ecdsa::PrivateKey;
use bitcoin::util::taproot::TapTweakHash;

use std::env;

#[allow(dead_code)]
fn print_random_char() {
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

    std::process::exit(0);
}

#[allow(dead_code)]
fn print_rng_gen() {
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

    let mut b_rng = bitcoin::secp256k1::rand::thread_rng();
    let b: f64 = b_rng.gen(); // generates a float between 0 and 1
    print!("b={:?}\n", &b);

    #[cfg(debug_assertions)]
    print_random_char();

    std::process::exit(0);
}

fn main() {
    #[cfg(debug_assertions)]
    print_rng_gen();

    let mut rng = OsRng::new().unwrap();

    use std::str::FromStr;
    #[allow(unused_variables)]
    let secret_key = secp256k1::SecretKey::from_str(
        "0000000000000000000000000000000000000000000000000000000000000001",
    )
    .unwrap();
    //#[cfg(debug_assertions)]
    print!(
        //"secret_key.display_secret()={:}\n",
        "{:}\n",
        secret_key.display_secret()
    );
    match String::from_str(&format!("{:}", secret_key.display_secret())) {
        Ok(s) => {
            for c in s.chars() {
                print!("{}", c);
            }
        }
        Err(_) => println!("Invalid UTF-8 sequence"),
    }
    print!("\n");

    use bip39::Language;
    use bip39::Mnemonic;

    //let m = Mnemonic::generate_in_with(&mut rng, Language::English, 24).unwrap();
    //for (i, word) in m.word_iter().enumerate() {
    //    print!("{} ", word);
    //}
    //print!("\n");

    // REF: https://docs.rs/bip39/latest/bip39/struct.Mnemonic.html
    // Create a new English Mnemonic from the given entropy.
    // Entropy must be a multiple of 32 bits (32/8 = 4 bytes) and 128-256 bits in length.

    //           count: 1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16
    let count_12 = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let m = Mnemonic::from_entropy(&count_12).unwrap();
    print!("count_12: (1)\n");
    for (i, word) in m.word_iter().enumerate() {
        print!("count={}:{} ", i, word);
    }
    print!("\n");

    print!("count_12: (2)\n");
    let m = Mnemonic::from_entropy(&[0; 16]).unwrap();
    for (i, word) in m.word_iter().enumerate() {
        print!("count={}:{} ", i, word);
    }
    print!("\n");

    //           count: 1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20
    let count_20 = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    let m = Mnemonic::from_entropy(&count_20).unwrap();
    print!("bytes_15:\n");
    for (i, word) in m.word_iter().enumerate() {
        print!("count={}:{} ", i, word);
    }
    print!("\n");

    print!("count_24:\n");
    let m = Mnemonic::from_entropy(&[0; 32]).unwrap();
    for (i, word) in m.word_iter().enumerate() {
        print!("count={}:{} ", i, word);
    }
    print!("\n");

    print!("count_24:\n");
    let m = Mnemonic::from_entropy(&[0; 32]).unwrap();
    for (i, word) in m.word_iter().enumerate() {
        print!("count={}:{} ", i, word);
    }
    print!("\n");

    let args: Vec<String> = env::args().collect();
    let mut prefix: String = "bc1p000".to_string();

    if args.len() == 2 {
        //rust-vanitygen BC1P000
        prefix = args[1].to_lowercase();
    }
    if prefix.len() <= 4 {
        println!("try:\nrust-vanity-gen bc1p000 or tb1p000");
        return;
    }
    let mut network = Network::Signet;
    #[cfg(debug_assertions)]
    print!("network={}\n", network);
    if prefix.get(0..4) != Some("bc1p") {
        if prefix.get(0..4) == Some("tb1p") {
        } else {
            println!("Invalid prefix, must begin with bc1p or tb1p");
            return;
        }
    } else {
        network = Network::Bitcoin;
    }
    #[cfg(debug_assertions)]
    print!("network={}\n", network);
    //std::process::exit(0);

    const CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let prefix_split: Vec<&str> = prefix.split("1").collect();
    for _pc in prefix_split[0].chars() {
        #[cfg(debug_assertions)]
        print!("{}\n", _pc);
    }
    for pc in prefix_split[1].chars() {
        #[cfg(debug_assertions)]
        print!("{}\n", pc);
        if !CHARSET.contains(pc) {
            println!("Invalid character in prefix.\nUse:\n{}", CHARSET);
            return;
        }
    }

    let mut merkle_root: Vec<u8> = Vec::new();
    if args.len() == 3 {
        merkle_root = hex::decode(&args[2]).unwrap();
        #[cfg(debug_assertions)]
        print!("merkle_root={:?}\n", merkle_root);
    }
    if args.len() >= 4 {
        #[cfg(debug_assertions)]
        println!("try:\nrust-vanity-gen bc1p000 or tb1p000");
        return;
    }

    //let secp = bitcoin::secp256k1::Secp256k1::new();
    let secp = secp256k1::Secp256k1::new();

    let four: u64 = "4".parse().unwrap();
    assert_eq!(4, four);
    #[cfg(debug_assertions)]
    print!("four={:?}\n", four);
    let one: u64 = "0000000000000000000000000000000000000000000000000000000000000001"
        .parse()
        .unwrap();
    assert_eq!(1, one);
    #[cfg(debug_assertions)]
    print!("one={:?}\n", one);
    //#[allow(unreachable_code)]
    //std::process::exit(0);

    //use std::str::FromStr;
    #[allow(unused_variables)]
    let secret_key = secp256k1::SecretKey::from_str(
        "0000000000000000000000000000000000000000000000000000000000000001",
    )
    .unwrap();
    #[cfg(debug_assertions)]
    print!(
        "secret_key.display_secret()={:}\n",
        secret_key.display_secret()
    );
    #[cfg(debug_assertions)]
    print!(
        "secret_key.secret_bytes()={:?}\n",
        secret_key.secret_bytes()
    );
    #[cfg(debug_assertions)]
    print!("secret_key={:?}\n", secret_key);
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
    #[cfg(debug_assertions)]
    print!("       public_key=\n      {:?}\n", public_key);
    #[cfg(debug_assertions)]
    print!("x_only_public_key=\n{:?}\n", public_key.x_only_public_key());

    use secp256k1::{Keypair, Scalar, Secp256k1, XOnlyPublicKey};

    let tweak = Scalar::random();

    let original = public_key;

    let (xonly, _parity) = public_key.x_only_public_key();
    let tweaked = xonly
        .add_tweak(&secp, &tweak)
        .expect("Improbable to fail with a randomly generated tweak");
    #[cfg(debug_assertions)]
    print!("          tweaked=\n{:?}\n", tweaked);

    #[allow(unreachable_code)]
    //std::process::exit(0);
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let count = 0;
    loop {
        let mut merkle_root: Vec<u8> = Vec::new();

        let (internal_seckey, internal_pubkey) = secp.generate_schnorrsig_keypair(&mut rng);
        #[cfg(debug_assertions)]
        print!("internal_seckey={:?}\n", internal_seckey);
        #[cfg(debug_assertions)]
        print!("internal_pubkey={:?}\n", internal_pubkey);

        let mut tweak: Vec<u8> = Vec::new();
        #[cfg(debug_assertions)]
        print!("tweak={:?}\n", tweak);
        tweak.extend_from_slice(&internal_pubkey.serialize());
        #[cfg(debug_assertions)]
        print!("tweak.extend_from_slice={:?}\n", tweak);
        tweak.extend_from_slice(&merkle_root);
        #[cfg(debug_assertions)]
        print!("tweak.extend_from_slice={:?}\n", tweak);
        let mut engine = TapTweakHash::engine();
        engine.input(&tweak);
        let tweak_value: [u8; 32] = TapTweakHash::from_engine(engine).into_inner();
        #[cfg(debug_assertions)]
        print!("tweak.value={:?}\n", tweak_value);

        let mut output_seckey = internal_seckey.clone();
        output_seckey.tweak_add_assign(&secp, &tweak_value).unwrap();

        let output_pubkey = PublicKey::from_keypair(&secp, &output_seckey);

        let mut addr = Address::p2tr(output_pubkey, Network::Signet);
        if network == Network::Bitcoin {
            addr = Address::p2tr(output_pubkey, Network::Bitcoin);
        } else {
            addr = Address::p2tr(output_pubkey, Network::Signet);
        }

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
