extern crate ed2curve25519;

use thrussh_keys::load_secret_key;
use rpassword::prompt_password_stdout;
use thrussh_keys::key::KeyPair;
use thrussh_keys::Error;
use base64;
use ed2curve25519::ed25519_to_curve25519;
use std::env::args;

fn main() {
    let path = args().skip(1).next().unwrap_or("id_ed25519".to_string());
    let pass = || Some(prompt_password_stdout("Password: ").unwrap_or("".to_string())).filter(|p| p.len() > 0).map(|p| p.as_bytes().to_vec());
    let key = match load_secret_key(&path, None) {
     Err(Error::KeyIsEncrypted) => {
      let pass = pass();
      load_secret_key(&path, pass.as_ref().map(|x| &**x)).unwrap()
     }
     Err(err) => panic!(err),
     Ok(key) => key
    };
    if let KeyPair::Ed25519(ref secret) = key {
     let curve = ed25519_to_curve25519(&secret.key).expect("Failed to convert key").to_vec();
     let base = base64::encode(&curve);
     println!("{}", base);
    } else {
     eprintln!("Not an ed25519 key!")
    }
}
