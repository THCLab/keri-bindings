use std::convert::TryInto;

use keri::{
    event::sections::threshold::SignatureThreshold,
    event_message::parse::message,
    prefix::{BasicPrefix, IdentifierPrefix, Prefix, SelfSigningPrefix},
};
use napi::{
    CallContext, Env, JsBoolean, JsBuffer, JsNumber, JsObject, JsString, JsUndefined, Property,
    Result as JsResult,
};
use napi_derive::{js_function, module_exports};
pub mod kel;
use kel::{event_generator::PublicKeysConfig, KEL};
use simple_config_parser::config::Config;

#[module_exports]
pub fn init(mut exports: JsObject, env: Env) -> JsResult<()> {
    let controller_class = env.define_class(
        "Controller",
        load_controller,
        &[
            Property::new(&env, "get_prefix")?.with_method(get_prefix),
            Property::new(&env, "get_kel")?.with_method(get_kel),
            Property::new(&env, "rotate")?.with_method(rotate),
            Property::new(&env, "finalize_rotation")?.with_method(finalize_rotation),
            Property::new(&env, "process")?.with_method(process),
            Property::new(&env, "get_current_public_key")?.with_method(get_current_public_key),
            Property::new(&env, "verify")?.with_method(verify),
        ],
    )?;
    exports.set_named_property("Controller", controller_class)?;
    exports.create_named_method("incept", incept)?;
    exports.create_named_method("finalize_incept", finalize_inception)?;

    Ok(())
}

#[js_function(2)]
fn finalize_inception(ctx: CallContext) -> JsResult<JsString> {
    let icp = ctx.get::<JsBuffer>(0)?.into_value()?.to_vec();
    let signatures = get_signature_array_argument(&ctx, 1)?;
    let mut cfg = Config::new(Some("settings.cfg"));
    // Read / parse config file
    cfg.read().ok().expect("There is no `settings.cfg` file");

    let path_str = cfg.get("db_path").ok_or(napi::Error::from_reason(
        "Missing `db_path` setting in settings.cfg".into(),
    ))?;
    let icp = message(&icp)
        .map_err(|e| napi::Error::from_reason(e.to_string()))?
        .1
        .event_message;
    let kel = KEL::finalize_incept(&path_str, &icp, signatures)
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;
    let identifier = kel.get_prefix().to_str();
    ctx.env.create_string(&identifier)
}

#[js_function(1)]
fn load_controller(ctx: CallContext) -> JsResult<JsUndefined> {
    let prefix = ctx
        .get::<JsString>(0)?
        .into_utf8()
        .map_err(|_e| napi::Error::from_reason("Missing identifier prefix parameter".into()))?
        .as_str()?
        .to_owned();

    let mut cfg = Config::new(Some("settings.cfg"));
    // Read / parse config file
    cfg.read()
        .ok()
        .ok_or(napi::Error::from_reason("Can't read a config file".into()))?;

    let path_str = cfg.get("db_path").ok_or(napi::Error::from_reason(
        "Missing `db_path` setting in settings.cfg".into(),
    ))?;
    let prefix: IdentifierPrefix = prefix.parse().expect("Can't parse signature");
    let kel =
        KEL::load_kel(&path_str, prefix).map_err(|e| napi::Error::from_reason(e.to_string()))?;
    let mut this: JsObject = ctx.this_unchecked();
    ctx.env.wrap(&mut this, kel)?;
    ctx.env.get_undefined()
}

fn get_keys_settings_argument(
    key_object: JsObject,
) -> JsResult<(BasicPrefix, BasicPrefix, Option<String>)> {
    let curr_pk: BasicPrefix = key_object
        .get_element::<JsString>(0)?
        .into_utf8()?
        .as_str()?
        .parse()
        .map_err(|_e| napi::Error::from_reason("Can't pase public key prefix".into()))?;
    let next_pk: BasicPrefix = key_object
        .get_element::<JsString>(1)?
        .into_utf8()?
        .as_str()?
        .parse()
        .map_err(|_e| napi::Error::from_reason("Can't pase public key prefix".into()))?;
    let threshold = match key_object.get_element::<JsString>(2) {
        Ok(t) => Some(t.into_utf8()?.as_str()?.to_string()),
        Err(_) => None,
    };

    Ok((curr_pk, next_pk, threshold))
}

fn get_keys_array_argument(ctx: &CallContext, arg_index: usize) -> JsResult<PublicKeysConfig> {
    let cur = ctx
        .get::<JsObject>(arg_index)
        .map_err(|_e| napi::Error::from_reason("Missing keys parameter".into()))?;
    let len = if cur.is_array()? {
        cur.get_array_length()?
    } else {
        0
    };
    let mut current: Vec<BasicPrefix> = vec![];
    let mut next: Vec<BasicPrefix> = vec![];
    let mut thresholds: Vec<Option<String>> = vec![];
    for i in 0..len {
        let val: JsObject = cur.get_element(i)?;
        let (cur, nxt, threshold) = get_keys_settings_argument(val)?;
        current.push(cur);
        next.push(nxt);
        thresholds.push(threshold);
    }

    let threshold = if thresholds.iter().all(|t| t.is_none()) {
        let threshold: Result<i32, _> = ctx.get::<JsNumber>(1)?.try_into();
        match threshold {
            Ok(threshold) => SignatureThreshold::simple(threshold as u64),
            Err(_) => {
                // Set default threshold if not provided
                SignatureThreshold::simple(1)
            }
        }
    } else {
        // Check if threshold is set for all keys
        let thres: JsResult<Vec<(u64, u64)>> = thresholds
            .into_iter()
            .map(|t| {
                t.ok_or(napi::Error::from_reason(
                    "Missing threshold settings. ".into(),
                ))
            })
            .map(|t| -> JsResult<_> {
                let unwrapped_t = t?;
                let mut split = unwrapped_t.split("/");
                Ok((
                    split
                        .next()
                        .ok_or(napi::Error::from_reason(
                            "Wrong threshold format. Should be fraction".into(),
                        ))?
                        .parse()
                        .map_err(|_e| {
                            napi::Error::from_reason(
                                "Wrong threshold format. Can't parse dividend".into(),
                            )
                        })?,
                    split
                        .next()
                        .ok_or(napi::Error::from_reason(
                            "Wrong threshold format. Should be fraction".into(),
                        ))?
                        .parse()
                        .map_err(|_e| {
                            napi::Error::from_reason(
                                "Wrong threshold format. Can't parse divisor".into(),
                            )
                        })?,
                ))
            })
            .collect();
        SignatureThreshold::single_weighted(thres?)
    };

    Ok(PublicKeysConfig {
        current,
        next,
        threshold,
    })
}

fn get_signature_array_argument(
    ctx: &CallContext,
    arg_index: usize,
) -> JsResult<Vec<SelfSigningPrefix>> {
    let signatures = ctx
        .get::<JsObject>(arg_index)
        .map_err(|_e| napi::Error::from_reason("Missing signatures parameter".into()))?;
    let len = if signatures.is_array()? {
        signatures.get_array_length()?
    } else {
        0
    };
    let mut parsed_signatures: Vec<SelfSigningPrefix> = vec![];
    for i in 0..len {
        let val: JsString = signatures.get_element(i)?;
        let bp = val
            .into_utf8()?
            .as_str()?
            .parse()
            .map_err(|_e| napi::Error::from_reason("Can't parse signature prefix".into()))?;
        parsed_signatures.push(bp);
    }
    Ok(parsed_signatures)
}

#[js_function(2)]
fn incept(ctx: CallContext) -> JsResult<JsBuffer> {
    let pub_keys = get_keys_array_argument(&ctx, 0)?;

    let icp = KEL::incept(&pub_keys)
        .map_err(|e| napi::Error::from_reason(e.to_string()))?
        .serialize()
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;

    ctx.env.create_buffer_copy(&icp).map(|b| b.into_raw())
}

#[js_function(0)]
fn get_prefix(ctx: CallContext) -> JsResult<JsString> {
    let this: JsObject = ctx.this_unchecked();
    let kel: &KEL = ctx.env.unwrap(&this)?;
    let preifx = kel.get_prefix().to_str();
    ctx.env.create_string(&preifx)
}

#[js_function(0)]
fn get_kel(ctx: CallContext) -> JsResult<JsString> {
    let this: JsObject = ctx.this_unchecked();
    let kel: &KEL = ctx.env.unwrap(&this)?;
    let kel_str = match kel
        .get_kel()
        .map_err(|e| napi::Error::from_reason(e.to_string()))?
    {
        Some(kel) => String::from_utf8(kel).map_err(|e| napi::Error::from_reason(e.to_string()))?,
        None => "".to_owned(),
    };
    ctx.env.create_string(&kel_str)
}

#[js_function(2)]
fn rotate(ctx: CallContext) -> JsResult<JsBuffer> {
    let pub_keys = get_keys_array_argument(&ctx, 0)?;

    let this: JsObject = ctx.this_unchecked();
    let kel: &mut KEL = ctx.env.unwrap(&this)?;
    let rot_event = kel
        .rotate(&pub_keys)
        .map_err(|e| napi::Error::from_reason(e.to_string()))?
        .serialize()
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;
    ctx.env.create_buffer_copy(&rot_event).map(|b| b.into_raw())
}

#[js_function(2)]
fn finalize_rotation(ctx: CallContext) -> JsResult<JsBoolean> {
    let rot = ctx
        .get::<JsBuffer>(0)?
        .into_value() //?.to_vec()
        .map_err(|_e| napi::Error::from_reason("Missing rotation event parameter".into()))?
        .to_vec();
    let signatures = get_signature_array_argument(&ctx, 1)?;

    let this: JsObject = ctx.this_unchecked();
    let kel: &KEL = ctx.env.unwrap(&this)?;

    let rot_result = kel.finalize_rotation(rot, signatures);
    ctx.env.get_boolean(rot_result.is_ok())
}

#[js_function(1)]
fn process(ctx: CallContext) -> JsResult<JsUndefined> {
    let stream = ctx
        .get::<JsBuffer>(0)?
        .into_value()
        .map_err(|_e| napi::Error::from_reason("Missing event stream parameter".into()))?
        .to_vec();
    let this: JsObject = ctx.this_unchecked();
    let kel: &KEL = ctx.env.unwrap(&this)?;
    kel.process_stream(&stream)
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;
    ctx.env.get_undefined()
}

#[js_function(1)]
fn get_current_public_key(ctx: CallContext) -> JsResult<JsObject> {
    let identifier: String = ctx
        .get::<JsString>(0)?
        .into_utf8()
        .map_err(|_e| napi::Error::from_reason("Missing identifier prefix parameter".into()))?
        .as_str()?
        .to_owned();
    let prefix: IdentifierPrefix = identifier
        .parse()
        .map_err(|_e| napi::Error::from_reason("Wrong identifeir prefix".into()))?;
    let this: JsObject = ctx.this_unchecked();
    let kel: &KEL = ctx.env.unwrap(&this)?;
    let mut key_array = ctx.env.create_array_with_length(2)?;
    let _key: Vec<_> = kel
        .get_current_public_keys(&prefix)
        .map_err(|_e| napi::Error::from_reason("Wrong identifeir prefix".into()))?
        .ok_or(napi::Error::from_reason(format!(
            "There is no keys for prefix {}",
            identifier
        )))?
        .iter()
        .enumerate()
        .map(|(i, key)| {
            key_array.set_element(i as u32, ctx.env.create_string_from_std(key.to_str())?)
        })
        .collect();
    Ok(key_array)
}

#[js_function(3)]
fn verify(ctx: CallContext) -> JsResult<JsBoolean> {
    let message = ctx
        .get::<JsBuffer>(0)?
        .into_value()
        .map_err(|_e| napi::Error::from_reason("Missing message parameter".into()))?
        .to_vec();
    let signatures = get_signature_array_argument(&ctx, 1)?;

    let identifier: String = ctx
        .get::<JsString>(2)?
        .into_utf8()
        .map_err(|_e| napi::Error::from_reason("Missing identifier prefix parameter".into()))?
        .as_str()?
        .to_owned();
    let this: JsObject = ctx.this_unchecked();
    let kel: &KEL = ctx.env.unwrap(&this)?;
    let prefix = identifier
        .parse()
        .map_err(|_e| napi::Error::from_reason("Wrong identifeir prefix".into()))?;

    ctx.env
        .get_boolean(kel.verify(&message, &signatures, &prefix).map_err(|e| {
            napi::Error::from_reason(format!("Error while verifing: {}", e.to_string()))
        })?)
}

#[js_function(4)]
fn verify_at_sn(ctx: CallContext) -> JsResult<JsBoolean> {
    let message = ctx
        .get::<JsBuffer>(0)?
        .into_value()
        .map_err(|_e| napi::Error::from_reason("Missing message parameter".into()))?
        .to_vec();
    let signature = ctx
        .get::<JsString>(0)?
        .into_utf8()
        .map_err(|_e| napi::Error::from_reason("Missing signature parameter".into()))?
        .as_str()?
        .to_owned();
    let identifier: String = ctx
        .get::<JsString>(2)?
        .into_utf8()
        .map_err(|_e| napi::Error::from_reason("Missing signature parameter".into()))?
        .as_str()?
        .to_owned();
    let sn: i64 = ctx.get::<JsNumber>(3)?.try_into()?;
    let this: JsObject = ctx.this_unchecked();
    let kel: &KEL = ctx.env.unwrap(&this)?;
    let prefix = identifier
        .parse()
        .map_err(|_e| napi::Error::from_reason("Wrong identifier prefix".into()))?;
    let signature: SelfSigningPrefix = signature
        .parse()
        .map_err(|_e| napi::Error::from_reason("Wrong signature prefix".into()))?;
    ctx.env.get_boolean(
        kel.verify_at_sn(&message, &signature, &prefix, sn as u64)
            .map_err(|e| {
                napi::Error::from_reason(format!("Error while verifing: {}", e.to_string()))
            })?,
    )
}

#[js_function(0)]
fn get_current_sn(ctx: CallContext) -> JsResult<JsNumber> {
    let this: JsObject = ctx.this_unchecked();
    let kel: &KEL = ctx.env.unwrap(&this)?;
    let sn = kel
        .current_sn()
        .map_err(|e| napi::Error::from_reason(format!("Can't get sn: {}", e.to_string())))?;
    ctx.env.create_int64(sn as i64)
}
