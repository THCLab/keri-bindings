use std::{
    path::PathBuf,
    slice,
    sync::{Arc, Mutex},
};

use controller::{error::ControllerError, identifier_controller::IdentifierController};
use flutter_rust_bridge::{frb, support::lazy_static};

use anyhow::{anyhow, Result};
pub use keri::{prefix::{BasicPrefix, IdentifierPrefix, SelfAddressingPrefix, SelfSigningPrefix}, derivation::{basic::Basic, self_addressing::SelfAddressing, self_signing::SelfSigning}};
pub use keri::keys::PublicKey as KeriPublicKey;
use keri::{
    actor::{event_generator, prelude::Message},
    event_parsing::{message::query_message, Attachment, EventType},
    oobi::{EndRole, LocationScheme, Role},
    prefix::Prefix,
};

use crate::utils::{join_keys_and_signatures, parse_attachment};
pub use controller::utils::OptionalConfig;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type KeyType = Basic;
#[frb(mirror(Basic))]
pub enum _Basic {
    ECDSAsecp256k1NT,
    ECDSAsecp256k1,
    Ed25519NT,
    Ed25519,
    Ed448NT,
    Ed448,
    X25519,
    X448,
}


pub type DigestType = SelfAddressing;
#[frb(mirror(SelfAddressing))]
pub enum _SelfAddressing {
    Blake3_256,
    SHA3_256,
    SHA2_256,
    Blake3_512,
    SHA3_512,
    Blake2B512,
    SHA2_512,
    Blake2B256(Vec<u8>),
    Blake2S256(Vec<u8>),
}

pub type SignatureType = SelfSigning;
#[frb(mirror(SelfSigning))]
pub enum _SelfSigning {
    Ed25519Sha512,
    ECDSAsecp256k1Sha256,
    Ed448,
}

#[derive(Clone)]
pub struct PublicKey(pub Box<BasicPrefix>);
impl PublicKey {
    pub fn new(kt: Basic, key_b64: String) -> PublicKey {
        PublicKey(Box::new(kt.derive(keri::keys::PublicKey::new(base64::decode(key_b64).unwrap()))))
    }
}

impl Default for PublicKey {
    fn default() -> Self {
        PublicKey::new(Basic::Ed25519, "".into())
    }
}

#[frb(mirror(KeriPublicKey))]
pub struct _KeriPublicKey {
    pub public_key: Vec<u8>
}

#[frb(mirror(BasicPrefix))]
pub struct _BasicPrefix {
    pub derivation: Basic,
    pub public_key: KeriPublicKey,
}

#[derive(Clone, Default)]
pub struct Digest(pub Box<SelfAddressingPrefix>);
impl Digest {
    pub fn new(dt: SelfAddressing, digest_data: Vec<u8>) -> Digest {
        Digest(Box::new(dt.derive(&digest_data)))
    }
}
#[frb(mirror(SelfAddressingPrefix))]
pub struct _SelfAddressingPrefix {
    pub derivation: SelfAddressing,
    pub digest: Vec<u8>,
}

#[derive(Clone)]
pub struct Signature(pub Box<SelfSigningPrefix>);
impl Signature {
    pub fn new_from_hex(st: SelfSigning, signature: String) -> Signature {
        Signature(Box::new(st.derive(hex::decode(signature).unwrap())))
    }

    pub fn new_from_b64(st: SelfSigning, signature: String) -> Signature {
        Signature(Box::new(st.derive(base64::decode(signature).unwrap())))
    }
}

#[frb(mirror(SelfSigningPrefix))]
pub struct _SelfSigningPrefix {
    pub derivation: SelfSigning,
    pub signature: Vec<u8>,
}

impl Identifier {
    pub fn from_str(id_str: String) -> Result<Identifier> {
        let id= match id_str.parse::<IdentifierPrefix>()? {
            IdentifierPrefix::Basic(bp) => Identifier::Basic(PublicKey(Box::new(bp))),
            IdentifierPrefix::SelfAddressing(sa) => Identifier::SelfAddressing(Digest(Box::new(sa))),
            IdentifierPrefix::SelfSigning(ss) => Identifier::SelfSigning(Signature(Box::new(ss))),
        };
        Ok(id)
    }

    pub fn to_str(&self) -> String {
        match self {
            Identifier::Basic(bp) => bp.0.to_str(),
            Identifier::SelfAddressing(sa) => sa.0.to_str(),
            Identifier::SelfSigning(ss) => ss.0.to_str(),
        }
    }
}

#[derive(Clone)]
pub enum Identifier {
    Basic(PublicKey),
    SelfAddressing(Digest),
    SelfSigning(Signature),
}

impl From<IdentifierPrefix> for Identifier {
    fn from(id: IdentifierPrefix) -> Self {
        match id {
            IdentifierPrefix::Basic(bp) => Identifier::Basic(PublicKey(Box::new(bp))),
            IdentifierPrefix::SelfAddressing(sa) => Identifier::SelfAddressing(Digest(Box::new(sa))),
            IdentifierPrefix::SelfSigning(ss) => Identifier::SelfSigning(Signature(Box::new(ss))),
        }
    }
}

impl Into<IdentifierPrefix> for Identifier {
    fn into(self) -> IdentifierPrefix {
        match self {
            Identifier::Basic(bp) => IdentifierPrefix::Basic(*bp.0),
            Identifier::SelfAddressing(sa) => IdentifierPrefix::SelfAddressing(*sa.0),
            Identifier::SelfSigning(ss) => IdentifierPrefix::SelfSigning(*ss.0),
        }
    }
}

pub struct Config {
    pub initial_oobis: String,
}

pub fn with_initial_oobis(config: Config, oobis_json: String) -> Config {
    Config {
        initial_oobis: oobis_json,
        ..config
    }
}

impl Config {
    pub(crate) fn build(&self) -> Result<OptionalConfig> {
        let oobis: Vec<LocationScheme> = serde_json::from_str(&self.initial_oobis)
            .map_err(|_e| anyhow!("Improper location scheme structure"))?;
        Ok(OptionalConfig {
            initial_oobis: Some(oobis),
            db_path: None,
        })
    }
}

lazy_static! {
    static ref KEL: Mutex<Option<Arc<controller::Controller>>> = Mutex::new(None);
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Can't lock the database")]
    DatabaseLockingError,

    #[error("Controller wasn't initialized")]
    ControllerInitializationError,

    // arguments parsing errors
    #[error("Can't parse controller prefix: {0}")]
    PrefixParseError(String),

    #[error("Can't parse self addressing identifier: {0}")]
    SaiParseError(String),

    #[error("Can't parse witness identifier: {0}")]
    WitnessParseError(String),

    #[error("Can't parse oobi json: {0}")]
    OobiParseError(String),

    #[error("base64 decode error")]
    Base64Error(#[from] base64::DecodeError),

    #[error("hex decode error")]
    HexError(#[from] hex::FromHexError),

    #[error("Can't resolve oobi: {0}")]
    OobiResolvingError(String),

    #[error("Missing issuer oobi")]
    MissingIssuerOobi,

    #[error("Utils error: {0}")]
    UtilsError(String),

    #[error("Improper event type")]
    EventTypeError,

    #[error(transparent)]
    KelError(#[from] ControllerError),
}

/// Helper function for tests. Enable to switch to use other database. Used to
/// simulate using multiple devices.
pub(crate) fn change_controller(db_path: String) -> Result<bool> {
    let config = OptionalConfig {
        db_path: Some(PathBuf::from(db_path)),
        initial_oobis: None,
    };
    let controller = controller::Controller::new(Some(config))?;

    *KEL.lock().map_err(|_e| Error::DatabaseLockingError)? = Some(Arc::new(controller));
    Ok(true)
}

pub fn init_kel(input_app_dir: String, optional_configs: Option<Config>) -> Result<bool> {
    let config = if let Some(config) = optional_configs {
        config
            .build()
            .map(|c| c.with_db_path(PathBuf::from(input_app_dir)))?
    } else {
        OptionalConfig {
            db_path: Some(PathBuf::from(input_app_dir)),
            initial_oobis: None,
        }
    };
    let is_initialized = {
        (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
            .as_ref()
            .is_some()
    };

    if !is_initialized {
        let controller = controller::Controller::new(Some(config))?;
        *KEL.lock().map_err(|_e| Error::DatabaseLockingError)? = Some(Arc::new(controller));
    }

    Ok(true)
}

pub fn incept(
    public_keys: Vec<PublicKey>,
    next_pub_keys: Vec<PublicKey>,
    // witnesses location scheme json
    witnesses: Vec<String>,
    witness_threshold: u64,
) -> Result<String> {
    let witnesses = witnesses
        .iter()
        .map(|wit| {
            serde_json::from_str::<LocationScheme>(wit)
                .map_err(|_e| Error::OobiParseError(wit.into()))
        })
        .collect::<Result<Vec<_>, _>>()
        // improper json structure or improper prefix
        .map_err(|e| anyhow!(e.to_string()))?;
    let public_keys = public_keys.into_iter().map(|pk| *pk.0).collect();
    let next_pub_keys = next_pub_keys.into_iter().map(|pk| *pk.0).collect();
    let icp = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .incept(public_keys, next_pub_keys, witnesses, witness_threshold)?;
    Ok(icp)
}

pub fn finalize_inception(event: String, signature: Signature) -> Result<Identifier> {
    let controller_id = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .finalize_inception(event.as_bytes(), &signature.0)?;
    Ok(Identifier::from(controller_id))
}

pub fn rotate(
    identifier: Identifier,
    current_keys: Vec<PublicKey>,
    new_next_keys: Vec<PublicKey>,
    // location schema json of witnesses
    witness_to_add: Vec<String>,
    // identifier of witnesses. Witness was previously added, so it's adresses
    // should be known.
    witness_to_remove: Vec<String>,
    witness_threshold: u64,
) -> Result<String> {
    let current_keys = current_keys.into_iter().map(|pk| *pk.0).collect();
    let new_next_keys = new_next_keys.into_iter().map(|pk| *pk.0).collect();
    // Parse location schema from string
    let witnesses_to_add = witness_to_add
        .iter()
        .map(|wit| {
            serde_json::from_str::<LocationScheme>(wit)
                .map_err(|_| Error::OobiParseError(wit.into()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let witnesses_to_remove = witness_to_remove
        .iter()
        .map(|wit| {
            wit.parse::<BasicPrefix>()
                .map_err(|_| Error::WitnessParseError(wit.into()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .rotate(
            identifier.into(),
            current_keys,
            new_next_keys,
            witnesses_to_add,
            witnesses_to_remove,
            witness_threshold,
        )?)
}

pub fn anchor(identifier: Identifier, data: String, algo: SelfAddressing) -> Result<String> {
    let digest = algo.derive(data.as_bytes());
    Ok((*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .anchor(identifier.into(), slice::from_ref(&digest))?)
}

pub fn anchor_digest(identifier: Identifier, sais: Vec<String>) -> Result<String> {
    let sais = sais
        .iter()
        .map(|sai| {
            sai.parse::<SelfAddressingPrefix>()
                .map_err(|_e| Error::SaiParseError(sai.into()))
        })
        .collect::<Result<Vec<_>, Error>>()?;

    Ok((*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .anchor(identifier.into(), &sais)?)
}

pub fn add_watcher(identifier: Identifier, watcher_oobi: String) -> Result<String> {
    let lc: LocationScheme =
        serde_json::from_str(&watcher_oobi).map_err(|_| Error::OobiParseError(watcher_oobi))?;
    if let IdentifierPrefix::Basic(_bp) = &lc.eid {
        (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
            .as_ref()
            .ok_or(Error::ControllerInitializationError)?
            .resolve_loc_schema(&lc)?;

        let add_watcher =
            event_generator::generate_end_role(&identifier.into(), &lc.eid, Role::Watcher, true)?;
        Ok(String::from_utf8(add_watcher.serialize()?)?)
    } else {
        Err(ControllerError::WrongWitnessPrefixError.into())
    }
}

pub fn finalize_event(identifier: Identifier, event: String, signature: Signature) -> Result<bool> {
    let controller = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .clone();
    let identifier_controller = IdentifierController::new(identifier.into(), controller);
    identifier_controller.finalize_event(event.as_bytes(), *signature.0)?;
    Ok(true)
}

/// Struct for collecting data that need to be signed: generated event and
/// exchange messages that are needed to forward multisig request to other group
/// participants.
pub struct GroupInception {
    pub icp_event: String,
    pub exchanges: Vec<String>,
}

pub fn incept_group(
    identifier: Identifier,
    participants: Vec<Identifier>,
    signature_threshold: u64,
    initial_witnesses: Vec<String>,
    witness_threshold: u64,
) -> Result<GroupInception> {
    let controller = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .clone();
    let initial_witnesses = initial_witnesses
        .iter()
        .map(|id| id.parse())
        .collect::<Result<_, _>>()?;
    let identifier_controller = IdentifierController::new(identifier.into(), controller);
    let (icp_to_sign, exns_to_sign) = identifier_controller.incept_group(
        participants.into_iter().map(|id| id.into()).collect(),
        signature_threshold,
        Some(initial_witnesses),
        Some(witness_threshold),
        None,
    )?;
    Ok(GroupInception {
        icp_event: icp_to_sign,
        exchanges: exns_to_sign,
    })
}

pub struct DataAndSignature {
    pub data: String,
    pub signature: Signature,
}

pub fn finalize_group_incept(
    identifier: Identifier,
    group_event: String,
    signature: Signature,
    to_forward: Vec<DataAndSignature>,
) -> Result<Identifier> {
    let controller = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .clone();

    let mut identifier_controller = IdentifierController::new(identifier.into(), controller);
    let group_identifier = identifier_controller.finalize_group_incept(
        group_event.as_bytes(),
        *signature.0,
        to_forward
            .iter()
            .map(
                |DataAndSignature {
                     data: exn,
                     signature,
                 }| { (exn.as_bytes(), *signature.0.clone()) },
            )
            .collect::<Vec<_>>(),
    )?;
    Ok(Identifier::from(group_identifier))
}

pub fn query_mailbox(
    who_ask: Identifier,
    about_who: Identifier,
    witness: Vec<String>,
) -> Result<Vec<String>> {
    let controller = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .clone();

    let identifier_controller = IdentifierController::new(who_ask.into(), controller);
    let witnesses: Vec<_> = witness
        .iter()
        .map(|wit| wit.parse::<BasicPrefix>().unwrap())
        .collect();
    let query = identifier_controller
        .query_mailbox(&about_who.into(), &witnesses)?
        .iter()
        .map(|qry| String::from_utf8(qry.serialize().unwrap()).unwrap())
        .collect::<Vec<_>>();

    Ok(query)
}

#[derive(Debug)]
pub enum Action {
    MultisigRequest,
    DelegationRequest,
}

#[derive(Debug)]
pub struct ActionRequired {
    pub action: Action,
    pub data: String,
    pub additiona_data: String,
}

pub fn finalize_mailbox_query(
    identifier: Identifier,
    query_event: String,
    signature: Signature,
) -> Result<Vec<ActionRequired>> {
    let controller = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .clone();
    let query = query_message(query_event.as_bytes()).unwrap().1;
    let mut identifier_controller = IdentifierController::new(identifier.into(), controller);

    match query {
        EventType::Qry(ref qry) => {
            let ar = identifier_controller.finalize_mailbox_query(vec![(qry.clone(), *signature.0)]);

            let out = ar?
                .iter()
                .map(|ar| -> Result<_> {
                    match ar {
                        controller::mailbox_updating::ActionRequired::MultisigRequest(
                            data,
                            exchanges,
                        ) => Ok(ActionRequired {
                            action: Action::MultisigRequest,
                            data: String::from_utf8(data.serialize()?).unwrap(),
                            additiona_data: String::from_utf8(exchanges.serialize()?).unwrap(),
                        }),
                        _ => {
                            todo!()
                        }
                    }
                })
                .collect();

            out
        }
        _ => Err(Error::EventTypeError.into()),
    }
}

pub fn resolve_oobi(oobi_json: String) -> Result<bool> {
    let lc: LocationScheme =
        serde_json::from_str(&oobi_json).map_err(|_e| Error::OobiParseError(oobi_json))?;
    (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .resolve_loc_schema(&lc)
        .map_err(|e| Error::OobiResolvingError(e.to_string()))?;
    Ok(true)
}

fn query_by_id(identifier: Identifier, query_id: String) -> Result<bool> {
    (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .query(&identifier.into(), &query_id)?;
    Ok(true)
}

pub fn query(identifier: Identifier, oobis_json: String) -> Result<bool> {
    #[derive(Serialize, Deserialize)]
    #[serde(untagged)]
    enum Oobis {
        LocScheme(LocationScheme),
        EndRole(EndRole),
    }
    let mut issuer_id: Option<String> = None;
    let oobis = serde_json::from_str::<Vec<Oobis>>(&oobis_json)
        .map_err(|_| Error::OobiParseError(oobis_json.clone()))?;
        let identifier_prefix: IdentifierPrefix = identifier.clone().into();
    for oobi in oobis {
        match &oobi {
            Oobis::LocScheme(lc) => {
                (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
                    .as_ref()
                    .ok_or(Error::ControllerInitializationError)?
                    .resolve_loc_schema(&lc)?;
            }
            Oobis::EndRole(er) => issuer_id = Some(er.cid.to_str()),
        };

        (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
            .as_ref()
            .ok_or(Error::ControllerInitializationError)?
            .send_oobi_to_watcher(&identifier_prefix, &serde_json::to_string(&oobi)?)?;
    }
    query_by_id(identifier, issuer_id.ok_or(Error::MissingIssuerOobi)?)
}

pub fn process_stream(stream: String) -> Result<bool> {
    (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .process_stream(stream.as_bytes())?;
    Ok(true)
}

pub fn get_kel(identifier: Identifier) -> Result<String> {
    let signed_event = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
        .as_ref()
        .ok_or(Error::ControllerInitializationError)?
        .storage
        .get_kel_messages_with_receipts(&identifier.into())?
        .ok_or(Error::KelError(ControllerError::UnknownIdentifierError))?
        .into_iter()
        .map(|event| Message::Notice(event).to_cesr().unwrap())
        .flatten()
        .collect();
    Ok(String::from_utf8(signed_event).unwrap())
}

pub struct PublicKeySignaturePair {
    pub key: PublicKey,
    pub signature: Signature,
}

/// Returns pairs: public key encoded in base64 and signature encoded in hex
pub fn get_current_public_key(attachment: String) -> Result<Vec<PublicKeySignaturePair>> {
    let att = parse_attachment(attachment.as_bytes())?;

    let keys = if let Attachment::SealSignaturesGroups(group) = att {
        let r = group
            .iter()
            .map(|(seal, signatures)| -> Result<Vec<_>, Error> {
                let current_keys = (*KEL.lock().map_err(|_e| Error::DatabaseLockingError)?)
                    .as_ref()
                    .ok_or(Error::ControllerInitializationError)?
                    .storage
                    .get_keys_at_event(&seal.prefix, seal.sn, &seal.event_digest)
                    .map_err(|e| Error::UtilsError(e.to_string()))?
                    .ok_or(Error::UtilsError("Can't find event of given seal".into()))?
                    .public_keys;
                join_keys_and_signatures(current_keys, signatures)
            })
            .collect::<Result<Vec<_>, Error>>();
        Ok(r.into_iter()
            .flatten()
            .flatten()
            .map(|(bp, sp)| PublicKeySignaturePair {
                key: PublicKey(Box::new(bp)),
                signature: Signature(Box::new(sp)),
            })
            .collect::<Vec<_>>())
    } else {
        Err(Error::UtilsError("Wrong attachment".into()))
    };
    Ok(keys?)
}
