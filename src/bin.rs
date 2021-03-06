extern crate ed2curve25519;

use base64;
use ed2curve25519::*;
use rpassword::prompt_password_stdout;
use std::env::args;
use std::error::Error as StdError;
use std::process::exit;
use thrussh_keys::key::{KeyPair, PublicKey};
use thrussh_keys::load_secret_key;
use thrussh_keys::Error;

fn main() {
    let path = args().skip(1).next().unwrap_or("id_ed25519".to_string());
    let pass = || {
        Some(prompt_password_stdout("Password: ").unwrap_or("".to_string()))
            .filter(|p| p.len() > 0)
            .map(|p| p.as_bytes().to_vec())
    };
    let key = match load_secret_key(&path, None) {
        Err(Error::KeyIsEncrypted) => {
            let pass = pass();
            load_secret_key(&path, pass.as_ref().map(|x| &**x)).expect("Failed to load keyfile")
        }
        Err(err) => {
            eprintln!("{}", err);
            exit(1)
        }
        Ok(key) => key,
    };
    let pubkey = key.clone_public_key();
    if let KeyPair::Ed25519(ref secret) = key {
        let curve = ed25519_to_curve25519(&secret.key).expect("Failed to convert key");
        let base = base64::encode(&curve[..]);
        println!("{}", base);
    } else {
        eprintln!("Not an ed25519 key!");
        exit(1);
    }

    if let PublicKey::Ed25519(ref key) = pubkey {
        let curve = ed25519_pk_to_curve25519(&key.key).expect("Failed to convert key");
        println!("{}", base64::encode(&curve[..]));
    }
}
