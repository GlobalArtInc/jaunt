use std::borrow::Cow;

use schemars::generate::SchemaSettings;
use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde_json::Value;

use crate::model::AdminPermission;
use crate::raw::RawDocument;

const SCHEMA_TITLE: &str = "Jaunt policy document";

impl JsonSchema for AdminPermission {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("AdminPermission")
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        let values: Vec<&str> = AdminPermission::ALL
            .iter()
            .map(AdminPermission::as_str)
            .collect();
        schemars::json_schema!({ "type": "string", "enum": values })
    }
}

pub fn policy_schema() -> Value {
    let generator = SchemaSettings::draft2020_12().into_generator();
    let mut document = generator.into_root_schema_for::<RawDocument>().to_value();
    if let Some(object) = document.as_object_mut() {
        object.insert("title".to_owned(), Value::String(SCHEMA_TITLE.to_owned()));
    }
    document
}

pub fn policy_schema_pretty() -> String {
    format!("{:#}", policy_schema())
}
