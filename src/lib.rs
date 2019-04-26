use libsodium_sys::{crypto_sign_ed25519_sk_to_curve25519, crypto_sign_ed25519_pk_to_curve25519};
use thrussh_keys::decode_secret_key;
use thrussh_keys::key::ed25519::SecretKey;
use thrussh_keys::key::KeyPair;
pub use thrussh_keys::Error;

pub fn ed25519_to_curve25519(ed25519_sk: &[u8]) -> Option<[u8; 32]> {
    let mut curve = [0u8; 32];
    Some(unsafe { crypto_sign_ed25519_sk_to_curve25519(curve.as_mut_ptr(), ed25519_sk.as_ptr()) })
        .filter(|err| *err != -1)
        .map(|_| curve)
}

pub fn ed25519_pk_to_curve25519(ed25519_pk: &[u8]) -> Option<[u8; 32]> {
    let mut curve = [0u8; 32];
    Some(unsafe { crypto_sign_ed25519_pk_to_curve25519(curve.as_mut_ptr(), ed25519_pk.as_ptr()) })
        .filter(|err| *err != -1)
        .map(|_| curve)
}

#[cfg(feature = "ssh")]
pub fn ssh_ed25519_to_curve25519<T: AsRef<str>>(
    pem: T,
    password: Option<&[u8]>,
) -> Result<[u8; 48], Error> {
    let ed = decode_secret_key(pem.as_ref(), password)?;
    if let KeyPair::Ed25519(ref secret) = ed {
        ed25519_to_curve25519(&secret.key).ok_or(Error::Unit)
    } else {
        Err(Error::CouldNotReadKey)
    }
}
