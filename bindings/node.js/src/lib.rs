use std::sync::Arc;

use cesrox::group::Group;
use controller::{
    self, identifier_controller::IdentifierController,
    mailbox_updating::ActionRequired as KeriActionRequired, BasicPrefix, CesrPrimitive,
    IdentifierPrefix, LocationScheme,
};
use keri::event_message::cesr_adapter::{parse_event_type, EventType};
use napi::{bindgen_prelude::*, tokio::sync::RwLock};
use napi_derive::napi;
use said::SelfAddressingIdentifier;
use utils::{configs, key_config::Key, signature_config::Signature};
pub mod utils;
use napi::bindgen_prelude::ToNapiValue;

#[napi(js_name = "KeyType")]
pub enum KeyType {
    ECDSAsecp256k1,
    Ed25519,
    Ed448,
    X25519,
    X448,
}

#[napi(object)]
#[derive(Debug)]
pub enum SignatureType {
    Ed25519Sha512,
    ECDSAsecp256k1Sha256,
    Ed448,
}

#[napi]
struct ActionRequired {
    action: KeriActionRequired,
}

#[napi]
struct Controller {
    kel_data: Arc<controller::Controller>,
}

#[napi]
impl Controller {
    #[napi(constructor)]
    pub fn init(config: Option<configs::Configs>) -> napi::Result<Self> {
        let optional_configs = config.map(|c| c.build().unwrap());

        let c = controller::Controller::new(optional_configs.unwrap_or_default())
            .map_err(|e| napi::Error::from_reason(e.to_string()))?;
        Ok(Controller {
            kel_data: Arc::new(c),
        })
    }

    #[napi]
    pub async fn incept(
        &self,
        pks: Vec<Key>,
        npks: Vec<Key>,
        // witnesses location schemes jsons
        witnesses: Vec<String>,
        witness_threshold: u32,
    ) -> napi::Result<Buffer> {
        let curr_keys = pks.iter().map(|k| k.to_prefix()).collect::<Vec<_>>();
        let next_keys = npks.iter().map(|k| k.to_prefix()).collect::<Vec<_>>();
        let witnesses = witnesses
            .iter()
            .map(|wit| {
                serde_json::from_str::<LocationScheme>(wit)
                    .map_err(|e| napi::Error::from_reason(e.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let icp = self
            .kel_data
            .incept(curr_keys, next_keys, witnesses, witness_threshold as u64)
            .await
            .map_err(|e| napi::Error::from_reason(e.to_string()))
            .unwrap();
        Ok(icp.as_bytes().into())
    }

    #[napi]
    pub async fn finalize_inception(
        &self,
        icp_event: Buffer,
        signatures: Vec<Signature>,
    ) -> napi::Result<IdController> {
        let ssp = &signatures.iter().map(|p| p.to_prefix()).collect::<Vec<_>>()
        // TODO
        [0];
        let incepted_identifier = self
            .kel_data
            .finalize_inception(&icp_event.to_vec(), ssp)
            .await
            .map_err(|e| napi::Error::from_reason(e.to_string()))?;
        Ok(IdController {
            controller: RwLock::new(IdentifierController::new(
                incepted_identifier,
                self.kel_data.clone(),
            )),
        })
    }

    #[napi]
    pub fn get_by_identifier(&self, id: String) -> napi::Result<IdController> {
        Ok(IdController::new(
            id.parse().unwrap(),
            self.kel_data.clone(),
        ))
    }

    #[napi]
    pub fn verify_from_cesr(&self, cesr_stream: String) -> Result<()> {
        self.kel_data
            .verify_from_cesr(&cesr_stream)
            .map_err(|e| napi::Error::from_reason(e.to_string()))
    }
}

#[napi]
struct IdController {
    controller: RwLock<IdentifierController>,
}

#[napi]
impl IdController {
    pub fn new(id: IdentifierPrefix, kel: Arc<controller::Controller>) -> Self {
        Self {
            controller: RwLock::new(IdentifierController::new(id, kel)),
        }
    }
    #[napi]
    pub async fn get_kel(&self) -> napi::Result<String> {
        Ok(self.controller.read().await.get_kel().unwrap())
    }

    #[napi]
    pub async fn get_id(&self) -> napi::Result<String> {
        Ok(self.controller.read().await.id.to_str())
    }

    #[napi]
    pub async fn rotate(
        &self,
        pks: Vec<Key>,
        npks: Vec<Key>,
        // loc scheme json of witness
        witnesses_to_add: Vec<String>,
        // identifiers of witness to remove
        witnesses_to_remove: Vec<String>,
        witness_threshold: u32,
    ) -> napi::Result<Buffer> {
        let curr_keys = pks.iter().map(|k| k.to_prefix()).collect::<Vec<_>>();
        let next_keys = npks.iter().map(|k| k.to_prefix()).collect::<Vec<_>>();
        let witnesses_to_add = witnesses_to_add
            .iter()
            .map(|wit| {
                serde_json::from_str::<LocationScheme>(wit)
                    .map_err(|e| e.to_string())
                    .map_err(|e| napi::Error::from_reason(e.to_string()))
            })
            .collect::<Result<Vec<_>, _>>();
        let witnesses_to_remove = witnesses_to_remove
            .iter()
            .map(|wit| {
                wit.parse::<BasicPrefix>()
                    .map_err(|e| e.to_string())
                    .map_err(|e| napi::Error::from_reason(e.to_string()))
            })
            .collect::<Result<Vec<_>, _>>();
        Ok(self
            .controller
            .read()
            .await
            .rotate(
                curr_keys,
                next_keys,
                witnesses_to_add?,
                witnesses_to_remove?,
                witness_threshold as u64,
            )
            .await
            .unwrap()
            .as_bytes()
            .into())
    }

    #[napi]
    pub async fn anchor(&self, anchored_data: Vec<String>) -> napi::Result<Buffer> {
        let sais: Result<Vec<_>> = anchored_data
            .iter()
            .map(|d| d.parse::<SelfAddressingIdentifier>().map_err(|e| napi::Error::from_reason(e.to_string())))
            .collect();
        Ok(self
            .controller
            .read()
            .await
            .anchor(&sais?)
            .unwrap()
            .as_bytes()
            .into())
    }

    #[napi]
    pub async fn finalize_event(
        &self,
        event: Buffer,
        signatures: Vec<Signature>,
    ) -> napi::Result<()> {
        let sigs = signatures
            .into_iter()
            .map(|s| s.to_prefix())
            .collect::<Vec<_>>()
            // TODO
            [0]
        .clone();
        self.controller
            .read()
            .await
            .finalize_event(&event.to_vec(), sigs)
            .await
            .map_err(|e| napi::Error::from_reason(e.to_string()))
    }

    #[napi]
    pub async fn notify_witnesses(&self) -> napi::Result<()> {
        self.controller
            .read()
            .await
            .notify_witnesses()
            .await
            .map_err(|e| napi::Error::from_reason(e.to_string()))?;
        Ok(())
    }

    #[napi]
    pub async fn query_mailbox(&self, witnesses: Vec<String>) -> napi::Result<Vec<Buffer>> {
        let witnesses: Result<Vec<_>> = witnesses
            .iter()
            .map(|wit_id| {
                wit_id
                    .parse::<BasicPrefix>()
                    .map_err(|_e| napi::Error::from_reason("Not basic prefix in witness list."))
            })
            .collect();
        let current_controller = self.controller.read().await;
        current_controller
            .query_mailbox(&current_controller.id, &witnesses?)
            .map_err(|e| napi::Error::from_reason(e.to_string()))?
            .iter()
            .map(|ev| {
                ev.encode()
                    .map(|enc| enc.into())
                    .map_err(|e| napi::Error::from_reason(e.to_string()))
            })
            .collect()
    }

    #[napi]
    pub async fn finalize_query(
        &self,
        event: Buffer,
        signature: Signature,
    ) -> napi::Result<Vec<ActionRequired>> {
        let query =
            parse_event_type(&event.to_vec()).map_err(|e| Error::from_reason(e.to_string()))?;
        match query {
            EventType::Qry(ref qry) => Ok(self
                .controller
                .write()
                .await
                .finalize_query(vec![(qry.clone(), signature.to_prefix())])
                .await
                .map_err(|e| Error::from_reason(e.to_string()))?
                .into_iter()
                .map(|ar| ActionRequired { action: ar })
                .collect()),
            _ => Err(Error::from_reason("Improper event type")),
        }
    }

    #[napi]
    pub async fn sign_data(&self, signature: Signature) -> napi::Result<String> {
        let current_controller = self.controller.read().await;
        let signature = current_controller
            .sign(signature.p.parse().unwrap(), 0)
            .unwrap();
        let group: Group = signature.into();

        Ok(group.to_cesr_str())
    }
}
