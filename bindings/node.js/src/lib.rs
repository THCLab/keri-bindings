use std::sync::{Arc};

use controller::{
    self, identifier_controller::IdentifierController, BasicPrefix, CesrPrimitive,
    IdentifierPrefix, LocationScheme, mailbox_updating::ActionRequired as KeriActionRequired, CryptoBox, KeyManager,
};
use keri::{event_message::cesr_adapter::{parse_event_type, EventType}, actor::event_generator::incept};
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
    action: KeriActionRequired
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
            controller: RwLock::new(IdentifierController::new(incepted_identifier, self.kel_data.clone())),
        })
    }

    #[napi]
    pub fn get_by_identifier(&self, id: String) -> napi::Result<IdController> {
        Ok(IdController::new(
            id.parse().unwrap(),
            self.kel_data.clone(),
        ))
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
            .read().await
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
        let sais = anchored_data
            .iter()
            .map(|d| d.parse::<SelfAddressingIdentifier>().unwrap())
            .collect::<Vec<_>>();
    Ok(self.controller.read().await.anchor(&sais).unwrap().as_bytes().into())
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
        self.controller.read().await
            .finalize_event(&event.to_vec(), sigs)
            .await
            .map_err(|e| napi::Error::from_reason(e.to_string()))
    }

    #[napi]
    pub async fn notify_witnesses(&self) -> napi::Result<()> {
        self.controller
            .read().await
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
        let current_controller = self.controller
            .read().await;
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
            EventType::Qry(ref qry) => {
                Ok(self
                .controller
                .write()
                .await
                .finalize_query(vec![(qry.clone(), signature.to_prefix())])
                .await
                .map_err(|e| Error::from_reason(e.to_string()))?
                .into_iter()
                .map(|ar| ActionRequired {action:ar})
                .collect())
            },
            _ => {Err(Error::from_reason("Improper event type"))},
        }
    }


    // #[napi]
    // pub fn sign_data(&self, signature: Signature) -> napi::Result<String> {
    //     let attached_signature = AttachedSignaturePrefix {
    //         index: 0,
    //         signature: signature.to_prefix(),
    //     };

    //     let event_seal = self
    //         .controller
    //         .get_last_establishment_event_seal()
    //         .map_err(|e| napi::Error::from_reason(e.to_string()))?;
    //     let att = Attachment::SealSignaturesGroups(vec![(event_seal, vec![attached_signature])]);
    //     Ok(att.to_cesr())
    // }
}

// #[napi]
// pub fn incept(
//     pks: Vec<Key>,
//     npks: Vec<Key>,
//     witnesses: Vec<String>,
//     witness_threshold: u32,
// ) -> napi::Result<Buffer> {
//     let curr_keys = pks.iter().map(|k| k.to_prefix()).collect::<Vec<_>>();
//     let next_keys = npks.iter().map(|k| k.to_prefix()).collect::<Vec<_>>();
//     let witnesses = witnesses
//         .iter()
//         .map(|wit| wit.parse::<BasicPrefix>().map_err(|e| e.to_string()))
//         .collect::<Result<Vec<_>, _>>()
//         .map_err(|e| napi::Error::from_reason(e.to_string()))?;
//     let icp = event_generator::incept(curr_keys, next_keys, witnesses, witness_threshold as u64)
//         .map_err(|e| napi::Error::from_reason(e.to_string()))
//         .unwrap();
//     Ok(icp.as_bytes().into())
// }

//     #[test]
//     fn test() {
//         let cont = Controller::init(None);
        
//         let witness_id = "BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC".to_string();
//         let wit_location = r#"{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://127.0.0.1:3232/"}"#.to_string();

//         // Setup signing identifier
//         let key_manager = CryptoBox::new().unwrap();
//         let current_b64key = base64::encode_config(key_manager.public_key().key(), base64::URL_SAFE);
//         let next_b64key = base64::encode_config(key_manager.next_public_key().key(), base64::URL_SAFE);

//         let pk = Key { p: todo!() } new_public_key(Basic::Ed25519, current_b64key)?;
//         let npk = new_public_key(Basic::Ed25519, next_b64key)?;
//         let icp_event = incept(vec![pk], vec![npk], vec![wit_location.clone()], 1)?;
//         let hex_signature = hex::encode(key_manager.sign(icp_event.as_bytes())?);
//         let signature = signature_from_hex(SelfSigning::Ed25519Sha512, hex_signature);
//         let signing_identifier = finalize_inception(icp_event, signature)?;
//         let oobi = format!(
//             r#"{{"cid":"{}","role":"witness","eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC"}}"#,
//             signing_identifier.id
//         );
//         println!("\n\noobi: {}\n\n", oobi);

//         // Publish own event to witnesses
//         notify_witnesses(signing_identifier.clone())?;

//         // Quering own mailbox to get receipts
//         // TODO always qry mailbox
//         let query = query_mailbox(
//             signing_identifier.clone(),
//             signing_identifier.clone(),
//             vec![witness_id.clone()],
//         )?;

//         for qry in query {
//             let hex_signature = hex::encode(key_manager.sign(qry.as_bytes())?);
//             let signature = signature_from_hex(SelfSigning::Ed25519Sha512, hex_signature);
//             finalize_query(signing_identifier.clone(), qry, signature)?;
//         }

//         // let signingn_idenifeir_kel = get_kel(signing_identifier.clone())?;

//         // Sign data by signing identifier
//         let data_to_sing = r#"{"hello":"world"}"#;
//         let hex_signature = hex::encode(key_manager.sign(data_to_sing.as_bytes())?);

//         let signature = signature_from_hex(SelfSigning::Ed25519Sha512, hex_signature);
//         let signed = sign_to_cesr(
//             signing_identifier.clone(),
//             data_to_sing.to_string(),
//             signature,
//         )?;
//         println!("signed: {}", &signed);

//         // Simulate using other device, with no signing identifier kel events inside.
//         change_controller(verifing_id_path.clone())?;

//         // Setup verifing identifier
//         let key_manager = CryptoBox::new().unwrap();
//         let current_b64key = base64::encode_config(key_manager.public_key().key(), base64::URL_SAFE);
//         let next_b64key = base64::encode_config(key_manager.next_public_key().key(), base64::URL_SAFE);

//         let pk = new_public_key(Basic::Ed25519, current_b64key)?;
//         let npk = new_public_key(Basic::Ed25519, next_b64key)?;
//         let icp_event = incept(vec![pk], vec![npk], vec![], 0)?;
//         let hex_signature = hex::encode(key_manager.sign(icp_event.as_bytes())?);
//         let signature = signature_from_hex(SelfSigning::Ed25519Sha512, hex_signature);

//         let verifing_identifier = finalize_inception(icp_event, signature)?;

//         // Configure watcher for verifing identifier
//         let watcher_oobi = r#"{"eid":"BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b","scheme":"http","url":"http://localhost:3236/"}"#.to_string();

//         let add_watcher_message = add_watcher(verifing_identifier.clone(), watcher_oobi)?;
//         println!(
//             "\nController generate end role message to add watcher: \n{}",
//             add_watcher_message
//         );
//         let hex_sig = hex::encode(key_manager.sign(add_watcher_message.as_bytes()).unwrap());
//         let signature = signature_from_hex(SelfSigning::Ed25519Sha512, hex_sig);

//         finalize_event(verifing_identifier.clone(), add_watcher_message, signature).unwrap();
//         let kel = get_kel(verifing_identifier.clone());
//         assert!(kel.is_ok());
//         println!("\n\nverifing id kel: {}\n\n", kel.unwrap());

//         let kel = get_kel(signing_identifier.clone());
//         // Unknown identifier error
//         assert!(kel.is_err());

//         let stream = format!("{}{}{}", wit_location, oobi, signed);
//         let splitted = split_oobis_and_data(stream)?;

//         // Provide signing identifier oobi to watcher.
//         for oobi in splitted.oobis {
//             send_oobi_to_watcher(verifing_identifier.clone(), oobi)?;
//         }

//         let kel = get_kel(signing_identifier.clone());
//         // Unknown identifier error
//         assert!(kel.is_err());

//         // Query watcher for results of resolving signing identifier oobis. It will provide signing identifier kel events.
//         let query = query_watchers(verifing_identifier.clone(), signing_identifier.clone())?;

//         for qry in query {
//             let hex_signature = hex::encode(key_manager.sign(qry.as_bytes())?);
//             let signature = signature_from_hex(SelfSigning::Ed25519Sha512, hex_signature);
//             finalize_query(verifing_identifier.clone(), qry, signature)?;
//         }

//         let kel = get_kel(signing_identifier.clone());
//         assert!(kel.is_ok());

//         // Verify provied signed message.
//         for acdc in splitted.credentials {
//             assert!(verify_from_cesr(acdc).unwrap());
//         }

//         Ok(())
// }