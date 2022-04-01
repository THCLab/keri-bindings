use std::{path::Path, sync::Arc};

use keri::{
    database::sled::SledEventDatabase,
    derivation::{basic::Basic, self_signing::SelfSigning},
    event::{event_data::EventData, sections::threshold::SignatureThreshold},
    event_message::{
        event_msg_builder::EventMsgBuilder, signed_event_message::Message, EventTypeTag,
    },
    event_parsing::message::key_event_message,
    keys::PublicKey as KeriPK,
    prefix::{AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, Prefix},
    processor::{event_storage::EventStorage, notification::NotificationBus, EventProcessor},
};
use thiserror::Error;


pub struct Kel {
    db: Arc<SledEventDatabase>,
    notification_bus: NotificationBus,
}
impl Kel {
    pub fn init(path: String) -> Self {
        let db = Arc::new(SledEventDatabase::new(Path::new(&path)).unwrap());
        Kel {
            db,
            notification_bus: NotificationBus::new(),
        }
    }

    pub fn incept(
        &self,
        public_keys: Vec<Vec<u8>>,
        next_pub_keys: Vec<Vec<u8>>,
        witnesses: Vec<String>,
        witness_threshold: u64,
    ) -> Result<String, KelError> {
        let witnesses = witnesses
            .iter()
            .map(|wit| wit.parse::<BasicPrefix>().map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_e| KelError::InceptionError)?;
        let pks = public_keys
            .into_iter()
            .map(|pk| Basic::Ed25519.derive(KeriPK::new(pk)))
            .collect();
        let npks = next_pub_keys
            .into_iter()
            .map(|pk| Basic::Ed25519.derive(KeriPK::new(pk)))
            .collect();
        let serialized_icp = EventMsgBuilder::new(EventTypeTag::Icp)
            .with_keys(pks)
            .with_next_keys(npks)
            .with_witness_list(witnesses.as_slice())
            .with_witness_threshold(&SignatureThreshold::Simple(witness_threshold))
            .build()
            .map_err(|_e| KelError::InceptionError)?
            .serialize().map_err(|_e| KelError::InceptionError)?;

        let icp = String::from_utf8(serialized_icp).map_err(|_e| KelError::InceptionError)?;
        Ok(icp)
    }

    pub fn rotate(
        &self,
        identifier: String,
        current_keys: Vec<Vec<u8>>,
        new_next_keys: Vec<Vec<u8>>,
        witness_to_add: Vec<String>,
        witness_to_remove: Vec<String>,
        witness_threshold: u64,
    ) -> Result<String, KelError> {
        let identifier = identifier
            .parse::<IdentifierPrefix>()
            .map_err(|_e| KelError::RotationError)?;
        let witnesses_to_add = witness_to_add
            .iter()
            .map(|wit| wit.parse::<BasicPrefix>().map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_e| KelError::RotationError)?;
        let witnesses_to_remove = witness_to_remove
            .iter()
            .map(|wit| wit.parse::<BasicPrefix>().unwrap())
            .collect::<Vec<_>>();
        let pks = current_keys
            .into_iter()
            .map(|pk| Basic::Ed25519.derive(KeriPK::new(pk)))
            .collect::<Vec<_>>();
        let npks = new_next_keys
            .into_iter()
            .map(|pk| Basic::Ed25519.derive(KeriPK::new(pk)))
            .collect::<Vec<_>>();
        let storage = EventStorage::new(self.db.clone());
        let state = storage
            .get_state(&identifier)
            .map_err(|_e| KelError::RotationError)?
            .ok_or_else(|| format!("no state for prefix {}", identifier.to_str()))
            .map_err(|_e| KelError::RotationError)?;
        let rot = EventMsgBuilder::new(EventTypeTag::Rot)
            .with_prefix(&identifier)
            .with_sn(state.sn + 1)
            .with_previous_event(&state.last_event_digest)
            .with_keys(pks)
            .with_next_keys(npks)
            .with_witness_to_add(&witnesses_to_add)
            .with_witness_to_remove(&witnesses_to_remove)
            .with_witness_threshold(&SignatureThreshold::Simple(witness_threshold))
            .build()
            .map_err(|_e| KelError::RotationError)?
            .serialize()
            .map_err(|_e| KelError::RotationError)?;
        String::from_utf8(rot).map_err(|_e| KelError::RotationError)
    }

    pub fn finalize_inception(
        &self,
        event: String,
        signature: Vec<u8>,
    ) -> Result<String, KelError> {
        let parsed_event = key_event_message(event.as_bytes())
            .map_err(|_e| KelError::ParseEventError)?
            .1;
        match parsed_event {
            keri::event_parsing::EventType::KeyEvent(ke) => {
                if let EventData::Icp(_) = ke.event.get_event_data() {
                    let processor = EventProcessor::new(self.db.clone());
                    // TODO set index
                    let sigs = vec![AttachedSignaturePrefix::new(
                        SelfSigning::Ed25519Sha512,
                        signature.to_vec(),
                        0,
                    )];
                    let signed_message = ke.sign(sigs, None);
                    let not = processor
                        .process(Message::Event(signed_message))
                        .map_err(|_e| KelError::ParseEventError)?;
                    self.notification_bus
                        .notify(&not)
                        .map_err(|_e| KelError::NotificationError)?;
                    // TODO check if id match
                }
                Ok(ke.event.get_prefix().to_string())
            }
            keri::event_parsing::EventType::Receipt(_) => todo!(),
        }
    }

    pub fn finalize_event(&self, event: String, signature: Vec<u8>) -> Result<(), KelError> {
        let parsed_event = key_event_message(event.as_bytes())
            .map_err(|_e| KelError::ParseEventError)?
            .1;
        match parsed_event {
            keri::event_parsing::EventType::KeyEvent(ke) => {
                let processor = EventProcessor::new(self.db.clone());
                // TODO set index
                let sigs = vec![AttachedSignaturePrefix::new(
                    SelfSigning::Ed25519Sha512,
                    signature.to_vec(),
                    0,
                )];
                let signed_message = ke.sign(sigs, None);
                let not = processor
                    .process(Message::Event(signed_message))
                    .map_err(|_e| KelError::ParseEventError)?;
                self.notification_bus
                    .notify(&not)
                    .map_err(|_e| KelError::NotificationError)
            }
            keri::event_parsing::EventType::Receipt(_) => todo!(),
        }
    }

    pub fn get_kel(&self, id: String) -> Result<String, KelError> {
        let storage = EventStorage::new(self.db.clone());
        String::from_utf8(
            storage
                .get_kel(
                    &id.parse::<IdentifierPrefix>()
                        .map_err(|_e| KelError::ParseEventError)?,
                )?
                .ok_or(KelError::UnknownIdentifierError)?,
        )
        .map_err(|_e| KelError::ParseEventError)
    }
}

#[derive(Error, Debug)]
pub enum KelError {
    #[error("can't generate inception event")]
    InceptionError,
    #[error("can't generate rotation event")]
    RotationError,
    #[error("can't parse event")]
    ParseEventError,
    #[error("can't notify")]
    NotificationError,
    #[error("unknown identifier")]
    UnknownIdentifierError,
    #[error("keri error")]
    KeriError(#[from] keri::error::Error),
}
