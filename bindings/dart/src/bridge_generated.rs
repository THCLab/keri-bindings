#![allow(
    non_camel_case_types,
    unused,
    clippy::redundant_closure,
    clippy::useless_conversion,
    clippy::unit_arg,
    clippy::double_parens,
    non_snake_case,
    clippy::too_many_arguments
)]
// AUTO GENERATED FILE, DO NOT EDIT.
// Generated by `flutter_rust_bridge`@ 1.82.3.

use crate::api::*;
use core::panic::UnwindSafe;
use flutter_rust_bridge::rust2dart::IntoIntoDart;
use flutter_rust_bridge::*;
use std::ffi::c_void;
use std::sync::Arc;

// Section: imports

// Section: wire functions

fn wire_new_public_key_impl(
    port_: MessagePort,
    kt: impl Wire2Api<KeyType> + UnwindSafe,
    key_b64_url_safe: impl Wire2Api<String> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, PublicKey, _>(
        WrapInfo {
            debug_name: "new_public_key",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_kt = kt.wire2api();
            let api_key_b64_url_safe = key_b64_url_safe.wire2api();
            move |task_callback| new_public_key(api_kt, api_key_b64_url_safe)
        },
    )
}
fn wire_signature_from_hex_impl(
    port_: MessagePort,
    st: impl Wire2Api<SignatureType> + UnwindSafe,
    signature: impl Wire2Api<String> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, Signature, _>(
        WrapInfo {
            debug_name: "signature_from_hex",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_st = st.wire2api();
            let api_signature = signature.wire2api();
            move |task_callback| Result::<_, ()>::Ok(signature_from_hex(api_st, api_signature))
        },
    )
}
fn wire_signature_from_b64_impl(
    port_: MessagePort,
    st: impl Wire2Api<SignatureType> + UnwindSafe,
    signature: impl Wire2Api<String> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, Signature, _>(
        WrapInfo {
            debug_name: "signature_from_b64",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_st = st.wire2api();
            let api_signature = signature.wire2api();
            move |task_callback| Result::<_, ()>::Ok(signature_from_b64(api_st, api_signature))
        },
    )
}
fn wire_with_initial_oobis_impl(
    port_: MessagePort,
    config: impl Wire2Api<Config> + UnwindSafe,
    oobis_json: impl Wire2Api<String> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, Config, _>(
        WrapInfo {
            debug_name: "with_initial_oobis",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_config = config.wire2api();
            let api_oobis_json = oobis_json.wire2api();
            move |task_callback| Result::<_, ()>::Ok(with_initial_oobis(api_config, api_oobis_json))
        },
    )
}
fn wire_change_controller_impl(port_: MessagePort, db_path: impl Wire2Api<String> + UnwindSafe) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, bool, _>(
        WrapInfo {
            debug_name: "change_controller",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_db_path = db_path.wire2api();
            move |task_callback| change_controller(api_db_path)
        },
    )
}
fn wire_init_kel_impl(
    port_: MessagePort,
    input_app_dir: impl Wire2Api<String> + UnwindSafe,
    optional_configs: impl Wire2Api<Option<Config>> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, bool, _>(
        WrapInfo {
            debug_name: "init_kel",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_input_app_dir = input_app_dir.wire2api();
            let api_optional_configs = optional_configs.wire2api();
            move |task_callback| init_kel(api_input_app_dir, api_optional_configs)
        },
    )
}
fn wire_incept_impl(
    port_: MessagePort,
    public_keys: impl Wire2Api<Vec<PublicKey>> + UnwindSafe,
    next_pub_keys: impl Wire2Api<Vec<PublicKey>> + UnwindSafe,
    witnesses: impl Wire2Api<Vec<String>> + UnwindSafe,
    witness_threshold: impl Wire2Api<u64> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, String, _>(
        WrapInfo {
            debug_name: "incept",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_public_keys = public_keys.wire2api();
            let api_next_pub_keys = next_pub_keys.wire2api();
            let api_witnesses = witnesses.wire2api();
            let api_witness_threshold = witness_threshold.wire2api();
            move |task_callback| {
                incept(
                    api_public_keys,
                    api_next_pub_keys,
                    api_witnesses,
                    api_witness_threshold,
                )
            }
        },
    )
}
fn wire_finalize_inception_impl(
    port_: MessagePort,
    event: impl Wire2Api<String> + UnwindSafe,
    signature: impl Wire2Api<Signature> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, Identifier, _>(
        WrapInfo {
            debug_name: "finalize_inception",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_event = event.wire2api();
            let api_signature = signature.wire2api();
            move |task_callback| finalize_inception(api_event, api_signature)
        },
    )
}
fn wire_rotate_impl(
    port_: MessagePort,
    identifier: impl Wire2Api<Identifier> + UnwindSafe,
    current_keys: impl Wire2Api<Vec<PublicKey>> + UnwindSafe,
    new_next_keys: impl Wire2Api<Vec<PublicKey>> + UnwindSafe,
    witness_to_add: impl Wire2Api<Vec<String>> + UnwindSafe,
    witness_to_remove: impl Wire2Api<Vec<String>> + UnwindSafe,
    witness_threshold: impl Wire2Api<u64> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, String, _>(
        WrapInfo {
            debug_name: "rotate",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_identifier = identifier.wire2api();
            let api_current_keys = current_keys.wire2api();
            let api_new_next_keys = new_next_keys.wire2api();
            let api_witness_to_add = witness_to_add.wire2api();
            let api_witness_to_remove = witness_to_remove.wire2api();
            let api_witness_threshold = witness_threshold.wire2api();
            move |task_callback| {
                rotate(
                    api_identifier,
                    api_current_keys,
                    api_new_next_keys,
                    api_witness_to_add,
                    api_witness_to_remove,
                    api_witness_threshold,
                )
            }
        },
    )
}
fn wire_anchor_impl(
    port_: MessagePort,
    identifier: impl Wire2Api<Identifier> + UnwindSafe,
    data: impl Wire2Api<String> + UnwindSafe,
    algo: impl Wire2Api<DigestType> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, String, _>(
        WrapInfo {
            debug_name: "anchor",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_identifier = identifier.wire2api();
            let api_data = data.wire2api();
            let api_algo = algo.wire2api();
            move |task_callback| anchor(api_identifier, api_data, api_algo)
        },
    )
}
fn wire_anchor_digest_impl(
    port_: MessagePort,
    identifier: impl Wire2Api<Identifier> + UnwindSafe,
    sais: impl Wire2Api<Vec<String>> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, String, _>(
        WrapInfo {
            debug_name: "anchor_digest",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_identifier = identifier.wire2api();
            let api_sais = sais.wire2api();
            move |task_callback| anchor_digest(api_identifier, api_sais)
        },
    )
}
fn wire_add_watcher_impl(
    port_: MessagePort,
    identifier: impl Wire2Api<Identifier> + UnwindSafe,
    watcher_oobi: impl Wire2Api<String> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, String, _>(
        WrapInfo {
            debug_name: "add_watcher",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_identifier = identifier.wire2api();
            let api_watcher_oobi = watcher_oobi.wire2api();
            move |task_callback| add_watcher(api_identifier, api_watcher_oobi)
        },
    )
}
fn wire_send_oobi_to_watcher_impl(
    port_: MessagePort,
    identifier: impl Wire2Api<Identifier> + UnwindSafe,
    oobis_json: impl Wire2Api<String> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, bool, _>(
        WrapInfo {
            debug_name: "send_oobi_to_watcher",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_identifier = identifier.wire2api();
            let api_oobis_json = oobis_json.wire2api();
            move |task_callback| send_oobi_to_watcher(api_identifier, api_oobis_json)
        },
    )
}
fn wire_finalize_event_impl(
    port_: MessagePort,
    identifier: impl Wire2Api<Identifier> + UnwindSafe,
    event: impl Wire2Api<String> + UnwindSafe,
    signature: impl Wire2Api<Signature> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, bool, _>(
        WrapInfo {
            debug_name: "finalize_event",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_identifier = identifier.wire2api();
            let api_event = event.wire2api();
            let api_signature = signature.wire2api();
            move |task_callback| finalize_event(api_identifier, api_event, api_signature)
        },
    )
}
fn wire_notify_witnesses_impl(
    port_: MessagePort,
    identifier: impl Wire2Api<Identifier> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, bool, _>(
        WrapInfo {
            debug_name: "notify_witnesses",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_identifier = identifier.wire2api();
            move |task_callback| notify_witnesses(api_identifier)
        },
    )
}
fn wire_broadcast_receipts_impl(
    port_: MessagePort,
    identifier: impl Wire2Api<Identifier> + UnwindSafe,
    witness_list: impl Wire2Api<Vec<Identifier>> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, bool, _>(
        WrapInfo {
            debug_name: "broadcast_receipts",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_identifier = identifier.wire2api();
            let api_witness_list = witness_list.wire2api();
            move |task_callback| broadcast_receipts(api_identifier, api_witness_list)
        },
    )
}
fn wire_incept_group_impl(
    port_: MessagePort,
    identifier: impl Wire2Api<Identifier> + UnwindSafe,
    participants: impl Wire2Api<Vec<Identifier>> + UnwindSafe,
    signature_threshold: impl Wire2Api<u64> + UnwindSafe,
    initial_witnesses: impl Wire2Api<Vec<String>> + UnwindSafe,
    witness_threshold: impl Wire2Api<u64> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, GroupInception, _>(
        WrapInfo {
            debug_name: "incept_group",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_identifier = identifier.wire2api();
            let api_participants = participants.wire2api();
            let api_signature_threshold = signature_threshold.wire2api();
            let api_initial_witnesses = initial_witnesses.wire2api();
            let api_witness_threshold = witness_threshold.wire2api();
            move |task_callback| {
                incept_group(
                    api_identifier,
                    api_participants,
                    api_signature_threshold,
                    api_initial_witnesses,
                    api_witness_threshold,
                )
            }
        },
    )
}
fn wire_finalize_group_incept_impl(
    port_: MessagePort,
    identifier: impl Wire2Api<Identifier> + UnwindSafe,
    group_event: impl Wire2Api<String> + UnwindSafe,
    signature: impl Wire2Api<Signature> + UnwindSafe,
    to_forward: impl Wire2Api<Vec<DataAndSignature>> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, Identifier, _>(
        WrapInfo {
            debug_name: "finalize_group_incept",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_identifier = identifier.wire2api();
            let api_group_event = group_event.wire2api();
            let api_signature = signature.wire2api();
            let api_to_forward = to_forward.wire2api();
            move |task_callback| {
                finalize_group_incept(
                    api_identifier,
                    api_group_event,
                    api_signature,
                    api_to_forward,
                )
            }
        },
    )
}
fn wire_query_mailbox_impl(
    port_: MessagePort,
    who_ask: impl Wire2Api<Identifier> + UnwindSafe,
    about_who: impl Wire2Api<Identifier> + UnwindSafe,
    witness: impl Wire2Api<Vec<String>> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, Vec<String>, _>(
        WrapInfo {
            debug_name: "query_mailbox",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_who_ask = who_ask.wire2api();
            let api_about_who = about_who.wire2api();
            let api_witness = witness.wire2api();
            move |task_callback| query_mailbox(api_who_ask, api_about_who, api_witness)
        },
    )
}
fn wire_query_watchers_impl(
    port_: MessagePort,
    who_ask: impl Wire2Api<Identifier> + UnwindSafe,
    about_who: impl Wire2Api<Identifier> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, Vec<String>, _>(
        WrapInfo {
            debug_name: "query_watchers",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_who_ask = who_ask.wire2api();
            let api_about_who = about_who.wire2api();
            move |task_callback| query_watchers(api_who_ask, api_about_who)
        },
    )
}
fn wire_finalize_query_impl(
    port_: MessagePort,
    identifier: impl Wire2Api<Identifier> + UnwindSafe,
    query_event: impl Wire2Api<String> + UnwindSafe,
    signature: impl Wire2Api<Signature> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, Vec<ActionRequired>, _>(
        WrapInfo {
            debug_name: "finalize_query",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_identifier = identifier.wire2api();
            let api_query_event = query_event.wire2api();
            let api_signature = signature.wire2api();
            move |task_callback| finalize_query(api_identifier, api_query_event, api_signature)
        },
    )
}
fn wire_resolve_oobi_impl(port_: MessagePort, oobi_json: impl Wire2Api<String> + UnwindSafe) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, bool, _>(
        WrapInfo {
            debug_name: "resolve_oobi",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_oobi_json = oobi_json.wire2api();
            move |task_callback| resolve_oobi(api_oobi_json)
        },
    )
}
fn wire_process_stream_impl(port_: MessagePort, stream: impl Wire2Api<String> + UnwindSafe) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, bool, _>(
        WrapInfo {
            debug_name: "process_stream",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_stream = stream.wire2api();
            move |task_callback| process_stream(api_stream)
        },
    )
}
fn wire_get_kel_impl(port_: MessagePort, identifier: impl Wire2Api<Identifier> + UnwindSafe) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, String, _>(
        WrapInfo {
            debug_name: "get_kel",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_identifier = identifier.wire2api();
            move |task_callback| get_kel(api_identifier)
        },
    )
}
fn wire_to_cesr_signature_impl(
    port_: MessagePort,
    identifier: impl Wire2Api<Identifier> + UnwindSafe,
    signature: impl Wire2Api<Signature> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, String, _>(
        WrapInfo {
            debug_name: "to_cesr_signature",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_identifier = identifier.wire2api();
            let api_signature = signature.wire2api();
            move |task_callback| to_cesr_signature(api_identifier, api_signature)
        },
    )
}
fn wire_sign_to_cesr_impl(
    port_: MessagePort,
    identifier: impl Wire2Api<Identifier> + UnwindSafe,
    data: impl Wire2Api<String> + UnwindSafe,
    signature: impl Wire2Api<Signature> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, String, _>(
        WrapInfo {
            debug_name: "sign_to_cesr",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_identifier = identifier.wire2api();
            let api_data = data.wire2api();
            let api_signature = signature.wire2api();
            move |task_callback| sign_to_cesr(api_identifier, api_data, api_signature)
        },
    )
}
fn wire_split_oobis_and_data_impl(port_: MessagePort, stream: impl Wire2Api<String> + UnwindSafe) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, SplittingResult, _>(
        WrapInfo {
            debug_name: "split_oobis_and_data",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_stream = stream.wire2api();
            move |task_callback| split_oobis_and_data(api_stream)
        },
    )
}
fn wire_verify_from_cesr_impl(port_: MessagePort, stream: impl Wire2Api<String> + UnwindSafe) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, bool, _>(
        WrapInfo {
            debug_name: "verify_from_cesr",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_stream = stream.wire2api();
            move |task_callback| verify_from_cesr(api_stream)
        },
    )
}
fn wire_incept_registry_impl(
    port_: MessagePort,
    identifier: impl Wire2Api<Identifier> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, RegistryData, _>(
        WrapInfo {
            debug_name: "incept_registry",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_identifier = identifier.wire2api();
            move |task_callback| incept_registry(api_identifier)
        },
    )
}
fn wire_issue_credential_impl(
    port_: MessagePort,
    identifier: impl Wire2Api<Identifier> + UnwindSafe,
    credential: impl Wire2Api<String> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, IssuanceData, _>(
        WrapInfo {
            debug_name: "issue_credential",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_identifier = identifier.wire2api();
            let api_credential = credential.wire2api();
            move |task_callback| issue_credential(api_identifier, api_credential)
        },
    )
}
fn wire_revoke_credential_impl(
    port_: MessagePort,
    identifier: impl Wire2Api<Identifier> + UnwindSafe,
    credential_said: impl Wire2Api<String> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, String, _>(
        WrapInfo {
            debug_name: "revoke_credential",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_identifier = identifier.wire2api();
            let api_credential_said = credential_said.wire2api();
            move |task_callback| revoke_credential(api_identifier, api_credential_said)
        },
    )
}
fn wire_query_tel_impl(
    port_: MessagePort,
    identifier: impl Wire2Api<Identifier> + UnwindSafe,
    registry_id: impl Wire2Api<String> + UnwindSafe,
    credential_said: impl Wire2Api<String> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, String, _>(
        WrapInfo {
            debug_name: "query_tel",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_identifier = identifier.wire2api();
            let api_registry_id = registry_id.wire2api();
            let api_credential_said = credential_said.wire2api();
            move |task_callback| query_tel(api_identifier, api_registry_id, api_credential_said)
        },
    )
}
fn wire_finalize_tel_query_impl(
    port_: MessagePort,
    identifier: impl Wire2Api<Identifier> + UnwindSafe,
    query_event: impl Wire2Api<String> + UnwindSafe,
    signature: impl Wire2Api<Signature> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, bool, _>(
        WrapInfo {
            debug_name: "finalize_tel_query",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_identifier = identifier.wire2api();
            let api_query_event = query_event.wire2api();
            let api_signature = signature.wire2api();
            move |task_callback| finalize_tel_query(api_identifier, api_query_event, api_signature)
        },
    )
}
fn wire_get_credential_state_impl(
    port_: MessagePort,
    identifier: impl Wire2Api<Identifier> + UnwindSafe,
    credential_said: impl Wire2Api<String> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, Option<String>, _>(
        WrapInfo {
            debug_name: "get_credential_state",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_identifier = identifier.wire2api();
            let api_credential_said = credential_said.wire2api();
            move |task_callback| get_credential_state(api_identifier, api_credential_said)
        },
    )
}
fn wire_notify_backers_impl(
    port_: MessagePort,
    identifier: impl Wire2Api<Identifier> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, bool, _>(
        WrapInfo {
            debug_name: "notify_backers",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_identifier = identifier.wire2api();
            move |task_callback| notify_backers(api_identifier)
        },
    )
}
fn wire_add_messagebox_impl(
    port_: MessagePort,
    identifier: impl Wire2Api<Identifier> + UnwindSafe,
    messagebox_oobi: impl Wire2Api<String> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, String, _>(
        WrapInfo {
            debug_name: "add_messagebox",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_identifier = identifier.wire2api();
            let api_messagebox_oobi = messagebox_oobi.wire2api();
            move |task_callback| add_messagebox(api_identifier, api_messagebox_oobi)
        },
    )
}
fn wire_get_messagebox_impl(port_: MessagePort, whose: impl Wire2Api<String> + UnwindSafe) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, Vec<String>, _>(
        WrapInfo {
            debug_name: "get_messagebox",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_whose = whose.wire2api();
            move |task_callback| get_messagebox(api_whose)
        },
    )
}
fn wire_new_from_str__static_method__Identifier_impl(
    port_: MessagePort,
    id_str: impl Wire2Api<String> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, Identifier, _>(
        WrapInfo {
            debug_name: "new_from_str__static_method__Identifier",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_id_str = id_str.wire2api();
            move |task_callback| Identifier::new_from_str(api_id_str)
        },
    )
}
fn wire_to_str__method__Identifier_impl(
    port_: MessagePort,
    that: impl Wire2Api<Identifier> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, String, _>(
        WrapInfo {
            debug_name: "to_str__method__Identifier",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_that = that.wire2api();
            move |task_callback| Result::<_, ()>::Ok(Identifier::to_str(&api_that))
        },
    )
}
fn wire_new__static_method__DataAndSignature_impl(
    port_: MessagePort,
    data: impl Wire2Api<String> + UnwindSafe,
    signature: impl Wire2Api<Signature> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap::<_, _, _, DataAndSignature, _>(
        WrapInfo {
            debug_name: "new__static_method__DataAndSignature",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_data = data.wire2api();
            let api_signature = signature.wire2api();
            move |task_callback| Result::<_, ()>::Ok(DataAndSignature::new(api_data, api_signature))
        },
    )
}
// Section: wrapper structs

#[derive(Clone)]
pub struct mirror_KeyType(KeyType);

#[derive(Clone)]
pub struct mirror_SignatureType(SignatureType);

// Section: static checks

const _: fn() = || {
    match None::<KeyType>.unwrap() {
        KeyType::ECDSAsecp256k1Nontrans => {}
        KeyType::ECDSAsecp256k1 => {}
        KeyType::Ed25519Nontrans => {}
        KeyType::Ed25519 => {}
        KeyType::Ed448Nontrans => {}
        KeyType::Ed448 => {}
        KeyType::X25519 => {}
        KeyType::X448 => {}
    }
    match None::<SignatureType>.unwrap() {
        SignatureType::Ed25519Sha512 => {}
        SignatureType::ECDSAsecp256k1Sha256 => {}
        SignatureType::Ed448 => {}
    }
};
// Section: allocate functions

// Section: related functions

// Section: impl Wire2Api

pub trait Wire2Api<T> {
    fn wire2api(self) -> T;
}

impl<T, S> Wire2Api<Option<T>> for *mut S
where
    *mut S: Wire2Api<T>,
{
    fn wire2api(self) -> Option<T> {
        (!self.is_null()).then(|| self.wire2api())
    }
}

impl Wire2Api<i32> for i32 {
    fn wire2api(self) -> i32 {
        self
    }
}

impl Wire2Api<KeyType> for i32 {
    fn wire2api(self) -> KeyType {
        match self {
            0 => KeyType::ECDSAsecp256k1Nontrans,
            1 => KeyType::ECDSAsecp256k1,
            2 => KeyType::Ed25519Nontrans,
            3 => KeyType::Ed25519,
            4 => KeyType::Ed448Nontrans,
            5 => KeyType::Ed448,
            6 => KeyType::X25519,
            7 => KeyType::X448,
            _ => unreachable!("Invalid variant for KeyType: {}", self),
        }
    }
}

impl Wire2Api<SignatureType> for i32 {
    fn wire2api(self) -> SignatureType {
        match self {
            0 => SignatureType::Ed25519Sha512,
            1 => SignatureType::ECDSAsecp256k1Sha256,
            2 => SignatureType::Ed448,
            _ => unreachable!("Invalid variant for SignatureType: {}", self),
        }
    }
}
impl Wire2Api<u64> for u64 {
    fn wire2api(self) -> u64 {
        self
    }
}
impl Wire2Api<u8> for u8 {
    fn wire2api(self) -> u8 {
        self
    }
}

// Section: impl IntoDart

impl support::IntoDart for Action {
    fn into_dart(self) -> support::DartAbi {
        match self {
            Self::MultisigRequest => 0,
            Self::DelegationRequest => 1,
        }
        .into_dart()
    }
}
impl support::IntoDartExceptPrimitive for Action {}
impl rust2dart::IntoIntoDart<Action> for Action {
    fn into_into_dart(self) -> Self {
        self
    }
}

impl support::IntoDart for ActionRequired {
    fn into_dart(self) -> support::DartAbi {
        vec![
            self.action.into_into_dart().into_dart(),
            self.data.into_into_dart().into_dart(),
            self.additiona_data.into_into_dart().into_dart(),
        ]
        .into_dart()
    }
}
impl support::IntoDartExceptPrimitive for ActionRequired {}
impl rust2dart::IntoIntoDart<ActionRequired> for ActionRequired {
    fn into_into_dart(self) -> Self {
        self
    }
}

impl support::IntoDart for Config {
    fn into_dart(self) -> support::DartAbi {
        vec![self.initial_oobis.into_into_dart().into_dart()].into_dart()
    }
}
impl support::IntoDartExceptPrimitive for Config {}
impl rust2dart::IntoIntoDart<Config> for Config {
    fn into_into_dart(self) -> Self {
        self
    }
}

impl support::IntoDart for DataAndSignature {
    fn into_dart(self) -> support::DartAbi {
        vec![
            self.data.into_into_dart().into_dart(),
            self.signature.into_into_dart().into_dart(),
        ]
        .into_dart()
    }
}
impl support::IntoDartExceptPrimitive for DataAndSignature {}
impl rust2dart::IntoIntoDart<DataAndSignature> for DataAndSignature {
    fn into_into_dart(self) -> Self {
        self
    }
}

impl support::IntoDart for GroupInception {
    fn into_dart(self) -> support::DartAbi {
        vec![
            self.icp_event.into_into_dart().into_dart(),
            self.exchanges.into_into_dart().into_dart(),
        ]
        .into_dart()
    }
}
impl support::IntoDartExceptPrimitive for GroupInception {}
impl rust2dart::IntoIntoDart<GroupInception> for GroupInception {
    fn into_into_dart(self) -> Self {
        self
    }
}

impl support::IntoDart for Identifier {
    fn into_dart(self) -> support::DartAbi {
        vec![self.id.into_into_dart().into_dart()].into_dart()
    }
}
impl support::IntoDartExceptPrimitive for Identifier {}
impl rust2dart::IntoIntoDart<Identifier> for Identifier {
    fn into_into_dart(self) -> Self {
        self
    }
}

impl support::IntoDart for IssuanceData {
    fn into_dart(self) -> support::DartAbi {
        vec![
            self.vc_id.into_into_dart().into_dart(),
            self.ixn.into_into_dart().into_dart(),
        ]
        .into_dart()
    }
}
impl support::IntoDartExceptPrimitive for IssuanceData {}
impl rust2dart::IntoIntoDart<IssuanceData> for IssuanceData {
    fn into_into_dart(self) -> Self {
        self
    }
}

impl support::IntoDart for mirror_KeyType {
    fn into_dart(self) -> support::DartAbi {
        match self.0 {
            KeyType::ECDSAsecp256k1Nontrans => 0,
            KeyType::ECDSAsecp256k1 => 1,
            KeyType::Ed25519Nontrans => 2,
            KeyType::Ed25519 => 3,
            KeyType::Ed448Nontrans => 4,
            KeyType::Ed448 => 5,
            KeyType::X25519 => 6,
            KeyType::X448 => 7,
        }
        .into_dart()
    }
}
impl support::IntoDartExceptPrimitive for mirror_KeyType {}
impl rust2dart::IntoIntoDart<mirror_KeyType> for KeyType {
    fn into_into_dart(self) -> mirror_KeyType {
        mirror_KeyType(self)
    }
}

impl support::IntoDart for PublicKey {
    fn into_dart(self) -> support::DartAbi {
        vec![
            self.derivation.into_into_dart().into_dart(),
            self.public_key.into_into_dart().into_dart(),
        ]
        .into_dart()
    }
}
impl support::IntoDartExceptPrimitive for PublicKey {}
impl rust2dart::IntoIntoDart<PublicKey> for PublicKey {
    fn into_into_dart(self) -> Self {
        self
    }
}

impl support::IntoDart for RegistryData {
    fn into_dart(self) -> support::DartAbi {
        vec![
            self.registry_id.into_into_dart().into_dart(),
            self.ixn.into_into_dart().into_dart(),
        ]
        .into_dart()
    }
}
impl support::IntoDartExceptPrimitive for RegistryData {}
impl rust2dart::IntoIntoDart<RegistryData> for RegistryData {
    fn into_into_dart(self) -> Self {
        self
    }
}

impl support::IntoDart for Signature {
    fn into_dart(self) -> support::DartAbi {
        vec![
            self.derivation.into_into_dart().into_dart(),
            self.signature.into_into_dart().into_dart(),
        ]
        .into_dart()
    }
}
impl support::IntoDartExceptPrimitive for Signature {}
impl rust2dart::IntoIntoDart<Signature> for Signature {
    fn into_into_dart(self) -> Self {
        self
    }
}

impl support::IntoDart for mirror_SignatureType {
    fn into_dart(self) -> support::DartAbi {
        match self.0 {
            SignatureType::Ed25519Sha512 => 0,
            SignatureType::ECDSAsecp256k1Sha256 => 1,
            SignatureType::Ed448 => 2,
        }
        .into_dart()
    }
}
impl support::IntoDartExceptPrimitive for mirror_SignatureType {}
impl rust2dart::IntoIntoDart<mirror_SignatureType> for SignatureType {
    fn into_into_dart(self) -> mirror_SignatureType {
        mirror_SignatureType(self)
    }
}

impl support::IntoDart for SplittingResult {
    fn into_dart(self) -> support::DartAbi {
        vec![
            self.oobis.into_into_dart().into_dart(),
            self.credentials.into_into_dart().into_dart(),
        ]
        .into_dart()
    }
}
impl support::IntoDartExceptPrimitive for SplittingResult {}
impl rust2dart::IntoIntoDart<SplittingResult> for SplittingResult {
    fn into_into_dart(self) -> Self {
        self
    }
}

// Section: executor

support::lazy_static! {
    pub static ref FLUTTER_RUST_BRIDGE_HANDLER: support::DefaultHandler = Default::default();
}

#[cfg(not(target_family = "wasm"))]
#[path = "bridge_generated.io.rs"]
mod io;
#[cfg(not(target_family = "wasm"))]
pub use io::*;
