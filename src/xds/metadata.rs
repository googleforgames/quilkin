use std::collections::{BTreeMap, HashSet};

use crate::config::extract_endpoint_tokens;
use crate::xds::envoy::config::core::v3::Metadata;
use prost_types::value::Kind;
use prost_types::Value as ProstValue;
use serde_json::map::Map as JsonMap;
use serde_json::value::Value as JSONValue;
use serde_json::Number as JSONNumber;

/// Converts an XDS Metadata object into endpoint specific values and JSON values.
pub fn parse_endpoint_metadata(
    metadata: Metadata,
) -> Result<(JSONValue, HashSet<Vec<u8>>), String> {
    let mut metadata = to_json_map(metadata)?;
    let tokens = extract_endpoint_tokens(&mut metadata)?;
    Ok((JSONValue::Object(metadata), tokens))
}

/// Converts an XDS Metadata object into an equivalent JSON map.
fn to_json_map(metadata: Metadata) -> Result<JsonMap<String, JSONValue>, String> {
    let mut map = JsonMap::new();

    for (key, prost_struct) in metadata.filter_metadata {
        map.insert(key, prost_map_to_json_value(prost_struct.fields)?);
    }

    Ok(map)
}

fn prost_kind_to_json_value(key: &str, kind: Kind) -> Result<JSONValue, String> {
    let v = match kind {
        Kind::NullValue(_) => JSONValue::Null,
        Kind::BoolValue(v) => JSONValue::Bool(v),
        Kind::NumberValue(v) => JSONValue::Number(
            JSONNumber::from_f64(v)
                .ok_or_else(|| format!("invalid f64 {:?} found under key {}", v, key))?,
        ),
        Kind::StringValue(v) => JSONValue::String(v),
        Kind::ListValue(v) => {
            let mut array = vec![];
            for v in v.values.into_iter().filter_map(|v| v.kind) {
                let v = prost_kind_to_json_value(key, v)?;
                array.push(v);
            }
            JSONValue::Array(array)
        }
        Kind::StructValue(v) => prost_map_to_json_value(v.fields)?,
    };

    Ok(v)
}

fn prost_map_to_json_value(prost_map: BTreeMap<String, ProstValue>) -> Result<JSONValue, String> {
    let mut map = JsonMap::new();

    for (key, prost_value) in prost_map {
        let prost_value = match prost_value.kind {
            Some(kind) => kind,
            None => continue,
        };

        let json_value = prost_kind_to_json_value(key.as_str(), prost_value)?;
        map.insert(key, json_value);
    }

    Ok(JSONValue::Object(map))
}

#[cfg(test)]
mod tests {
    use crate::xds::envoy::config::core::v3::Metadata;
    use crate::xds::metadata::{parse_endpoint_metadata, to_json_map};
    use prost_types::value::Kind;
    use prost_types::Struct as ProstStruct;
    use prost_types::{ListValue, Value as ProstValue};
    use serde_json::map::Map as JsonMap;
    use serde_json::value::Value as JSONValue;
    use std::collections::{BTreeMap, HashMap, HashSet};

    #[test]
    fn empty_metadata() {
        let metadata = Metadata {
            filter_metadata: HashMap::new(),
        };
        assert_eq!(to_json_map(metadata).unwrap(), JsonMap::new())
    }

    #[test]
    fn parse_metadata_data_types() {
        let expected = serde_json::json!({
            "k1": {},
            "k2": {
                "k2-true": true,
                "k2-number": 1234.0,
                "k2-2-element-list": [ 5678.0, "hello"]
            },
            "k3": {
                "k3-null": null
            }
        });

        let metadata = Metadata {
            filter_metadata: vec![
                (
                    "k1".into(),
                    ProstStruct {
                        fields: BTreeMap::new(),
                    },
                ),
                (
                    "k2".into(),
                    ProstStruct {
                        fields: vec![
                            (
                                "k2-true".into(),
                                ProstValue {
                                    kind: Some(Kind::BoolValue(true)),
                                },
                            ),
                            (
                                "k2-number".into(),
                                ProstValue {
                                    kind: Some(Kind::NumberValue(1234f64)),
                                },
                            ),
                            (
                                "k2-2-element-list".into(),
                                ProstValue {
                                    kind: Some(Kind::ListValue(ListValue {
                                        values: vec![
                                            ProstValue {
                                                kind: Some(Kind::NumberValue(5678f64)),
                                            },
                                            ProstValue {
                                                kind: Some(Kind::StringValue("hello".into())),
                                            },
                                        ],
                                    })),
                                },
                            ),
                        ]
                        .into_iter()
                        .collect(),
                    },
                ),
                (
                    "k3".into(),
                    ProstStruct {
                        fields: vec![(
                            "k3-null".into(),
                            ProstValue {
                                kind: Some(Kind::NullValue(1)),
                            },
                        )]
                        .into_iter()
                        .collect(),
                    },
                ),
            ]
            .into_iter()
            .collect(),
        };

        assert_eq!(JSONValue::Object(to_json_map(metadata).unwrap()), expected);
    }

    #[test]
    fn parse_nested_data_types() {
        let expected = serde_json::json!({
            "data": {
                "one": [2.0],
                "three": {
                    "four": ["five", { "six": 7.0 }],
                    "eight": 9.0
                },
                "ten": []
            }
        });

        let metadata = Metadata {
            filter_metadata: vec![(
                "data".into(),
                ProstStruct {
                    fields: vec![
                        (
                            "one".into(),
                            ProstValue {
                                kind: Some(Kind::ListValue(ListValue {
                                    values: vec![ProstValue {
                                        kind: Some(Kind::NumberValue(2f64)),
                                    }],
                                })),
                            },
                        ),
                        (
                            "three".into(),
                            ProstValue {
                                kind: Some(Kind::StructValue(ProstStruct {
                                    fields: vec![
                                        (
                                            "four".into(),
                                            ProstValue {
                                                kind: Some(Kind::ListValue(ListValue {
                                                    values: vec![
                                                        ProstValue {
                                                            kind: Some(Kind::StringValue(
                                                                "five".into(),
                                                            )),
                                                        },
                                                        ProstValue {
                                                            kind: Some(Kind::StructValue(
                                                                ProstStruct {
                                                                    fields: vec![(
                                                                        "six".into(),
                                                                        ProstValue {
                                                                            kind: Some(
                                                                                Kind::NumberValue(
                                                                                    7.0f64,
                                                                                ),
                                                                            ),
                                                                        },
                                                                    )]
                                                                    .into_iter()
                                                                    .collect(),
                                                                },
                                                            )),
                                                        },
                                                    ],
                                                })),
                                            },
                                        ),
                                        (
                                            "eight".into(),
                                            ProstValue {
                                                kind: Some(Kind::NumberValue(9.0f64)),
                                            },
                                        ),
                                    ]
                                    .into_iter()
                                    .collect(),
                                })),
                            },
                        ),
                        (
                            "ten".into(),
                            ProstValue {
                                kind: Some(Kind::ListValue(ListValue { values: vec![] })),
                            },
                        ),
                    ]
                    .into_iter()
                    .collect(),
                },
            )]
            .into_iter()
            .collect(),
        };

        assert_eq!(JSONValue::Object(to_json_map(metadata).unwrap()), expected);
    }

    #[test]
    fn prost_endpoint_metadata() {
        let expected = serde_json::json!({
            "user-field": {}
        });

        let metadata = Metadata {
            filter_metadata: vec![
                (
                    "user-field".into(),
                    ProstStruct {
                        fields: BTreeMap::new(),
                    },
                ),
                (
                    "quilkin.dev".into(),
                    ProstStruct {
                        fields: vec![(
                            "tokens".into(),
                            ProstValue {
                                kind: Some(Kind::ListValue(ListValue {
                                    values: vec![
                                        ProstValue {
                                            kind: Some(Kind::StringValue("MXg3aWp5Ng==".into())),
                                        },
                                        ProstValue {
                                            kind: Some(Kind::StringValue("OGdqM3YyaQ==".into())),
                                        },
                                    ],
                                })),
                            },
                        )]
                        .into_iter()
                        .collect(),
                    },
                ),
            ]
            .into_iter()
            .collect(),
        };

        let (metadata, tokens) = parse_endpoint_metadata(metadata).unwrap();

        assert_eq!(metadata, expected);
        assert_eq!(
            tokens,
            vec!["1x7ijy6".into(), "8gj3v2i".into()]
                .into_iter()
                .collect::<HashSet<_>>()
        );
    }

    #[test]
    fn prost_invalid_endpoint_metadata() {
        let invalid_values = vec![
            // Not a list.
            ProstValue {
                kind: Some(Kind::StringValue("MXg3aWp5Ng==".into())),
            },
            // Not a string value
            ProstValue {
                kind: Some(Kind::ListValue(ListValue {
                    values: vec![
                        ProstValue {
                            kind: Some(Kind::StringValue("MXg3aWp5Ng==".into())),
                        },
                        ProstValue {
                            kind: Some(Kind::NumberValue(12.0)),
                        },
                    ],
                })),
            },
            // Not a base64 string value
            ProstValue {
                kind: Some(Kind::ListValue(ListValue {
                    values: vec![ProstValue {
                        kind: Some(Kind::StringValue("cat".into())),
                    }],
                })),
            },
        ];

        for invalid in invalid_values {
            let metadata = Metadata {
                filter_metadata: vec![(
                    "quilkin.dev".into(),
                    ProstStruct {
                        fields: vec![("tokens".into(), invalid)].into_iter().collect(),
                    },
                )]
                .into_iter()
                .collect(),
            };

            assert!(parse_endpoint_metadata(metadata).is_err());
        }
    }
}
