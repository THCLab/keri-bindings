use std::str::FromStr;

use said::{derivation::{HashFunctionCode, HashFunction}, SelfAddressingIdentifier};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn derive( derivation: Derivation, data: &str,) -> String {
    let derivation = HashFunction::from(match derivation {
        Derivation::Blake3_256 => HashFunctionCode::Blake3_256,
        Derivation::Blake3_512 => HashFunctionCode::Blake3_512,
        Derivation::Blake2B512 => HashFunctionCode::Blake2B512,
        Derivation::Blake2B256 => HashFunctionCode::Blake2B256(vec![]),
        Derivation::Blake2S256 => HashFunctionCode::Blake2S256(vec![]),
        Derivation::SHA3_256 => HashFunctionCode::SHA3_256,
        Derivation::SHA2_256 => HashFunctionCode::SHA2_256,
        Derivation::SHA3_512 => HashFunctionCode::SHA3_512,
        Derivation::SHA2_512 => HashFunctionCode::SHA2_512,
    });
    derivation.derive(data.as_bytes()).to_string()
}

#[wasm_bindgen]
pub fn verify(sai_prefix: &str, data: &str) -> Result<bool, JsValue> {
    let sai = match SelfAddressingIdentifier::from_str(sai_prefix) {
        Ok(x) => x,
        Err(e) => return Err(e.to_string().into()),
    };
    Ok(sai.verify_binding(data.as_bytes()))
}

#[wasm_bindgen]
pub enum Derivation {
    Blake3_256,
    Blake3_512,
    Blake2B512,
    Blake2B256,
    Blake2S256,
    SHA3_256,
    SHA2_256,
    SHA3_512,
    SHA2_512,
}
