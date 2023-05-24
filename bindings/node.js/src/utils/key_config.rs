use cesrox::primitives::codes::basic::Basic;
use controller::BasicPrefix;
use controller::CesrPrimitive;
use napi::bindgen_prelude::Buffer;
use napi_derive::napi;

use crate::KeyType;

impl Into<Basic> for KeyType {
    fn into(self) -> Basic {
        match self {
            KeyType::ECDSAsecp256k1 => Basic::ECDSAsecp256k1Nontrans,
            KeyType::Ed25519 => Basic::Ed25519Nontrans,
            KeyType::Ed448 => Basic::Ed448Nontrans,
            KeyType::X25519 => Basic::X25519,
            KeyType::X448 => Basic::X448,
        }
    }
}

impl From<Basic> for KeyType {
    fn from(kd: Basic) -> Self {
        match kd {
            Basic::ECDSAsecp256k1Nontrans => KeyType::ECDSAsecp256k1,
            Basic::ECDSAsecp256k1 => KeyType::ECDSAsecp256k1,
            Basic::Ed25519Nontrans => KeyType::Ed25519,
            Basic::Ed25519 => KeyType::Ed25519,
            Basic::Ed448Nontrans => KeyType::Ed448,
            Basic::Ed448 => KeyType::Ed448,
            Basic::X25519 => KeyType::X25519,
            Basic::X448 => KeyType::X448,
        }
    }
}

#[napi]
pub struct PublicKey {
    pub prefix: String,
}
#[napi]
impl PublicKey {
    #[napi(constructor)]
    pub fn new(algorithm: KeyType, key: Buffer) -> Self {
        let d: Basic = algorithm.into();
        let pref = BasicPrefix::new(d, keri::keys::PublicKey::new(key.to_vec()));
        Self {
            prefix: pref.to_str(),
        }
    }

    #[napi]
    pub fn get_key(&self) -> Key {
        Key {
            p: self.prefix.clone(),
        }
    }
}

#[napi(object)]
pub struct Key {
    pub p: String,
}

impl Key {
    pub fn to_prefix(&self) -> BasicPrefix {
        self.p.parse().unwrap()
    }
}
