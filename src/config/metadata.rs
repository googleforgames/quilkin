use crate::config::{ENDPOINT_METADATA_KEY_PREFIX, ENDPOINT_METADATA_TOKEN_KEY};
use serde_json::map::Map as JsonMap;
use serde_json::value::Value as JSONValue;
use serde_json::Number as JSONNumber;
use serde_yaml::Value as YamlValue;
use std::collections::HashSet;

// Returns an empty map if no tokens exist.
pub fn extract_endpoint_tokens(
    metadata: &mut JsonMap<String, JSONValue>,
) -> Result<HashSet<Vec<u8>>, String> {
    let tokens = metadata.remove(ENDPOINT_METADATA_KEY_PREFIX)
        .map(|raw_value| {
            match raw_value {
                JSONValue::Object(mut object) => {
                    match object.remove(ENDPOINT_METADATA_TOKEN_KEY) {
                        Some(JSONValue::Array(raw_tokens)) => {
                            raw_tokens.into_iter().fold(Ok(HashSet::new()), |acc, val| {
                                let mut tokens = acc?;

                                let token = match val {
                                    JSONValue::String(token) =>
                                        base64::decode(token)
                                            .map_err(|err| format!(
                                                "key {}.{}: failed to decode token as a base64 string:{}",
                                                ENDPOINT_METADATA_KEY_PREFIX,
                                                ENDPOINT_METADATA_TOKEN_KEY,
                                                err
                                            )),
                                    _ => Err(format!(
                                        "invalid value in token list for key `{}`: value must a base64 string",
                                        ENDPOINT_METADATA_TOKEN_KEY
                                    ))
                                };

                                tokens.insert(token?);
                                Ok(tokens)
                            })
                        },
                        Some(_) => Err(format!(
                            "invalid data type for key `{}.{}`: value must be a list of base64 strings",
                            ENDPOINT_METADATA_KEY_PREFIX,
                            ENDPOINT_METADATA_TOKEN_KEY
                        )),
                        None => Ok(Default::default()),
                    }
                }
                _ => Err(format!("invalid data type for key `{}`: value must be an object", ENDPOINT_METADATA_KEY_PREFIX))
            }
        })
        .transpose()?;

    Ok(tokens.unwrap_or_default())
}

pub fn parse_endpoint_metadata_from_yaml(
    yaml: YamlValue,
) -> Result<(JSONValue, HashSet<Vec<u8>>), String> {
    let mapping = if let YamlValue::Mapping(mapping) = yaml {
        mapping
    } else {
        return Err("invalid endpoint metadata: value must be a yaml object".into());
    };

    let mut map = JsonMap::new();
    for (yaml_key, yaml_value) in mapping {
        let key = parse_yaml_key(yaml_key)?;
        let value = yaml_to_json_value(key.as_str(), yaml_value)?;
        map.insert(key, value);
    }

    let tokens = extract_endpoint_tokens(&mut map)?;

    Ok((JSONValue::Object(map), tokens))
}

fn yaml_to_json_value(key: &str, yaml: YamlValue) -> Result<JSONValue, String> {
    let json_value = match yaml {
        YamlValue::Null => JSONValue::Null,
        YamlValue::Bool(v) => JSONValue::Bool(v),
        YamlValue::Number(v) => match v.as_f64() {
            Some(v) => JSONValue::Number(
                JSONNumber::from_f64(v)
                    .ok_or_else(|| format!("invalid f64 `{:?}` provided for key `{}`", v, key))?,
            ),
            None => return Err(format!("failed to parse key `{}` as f64 number", key)),
        },
        YamlValue::String(v) => JSONValue::String(v),
        YamlValue::Sequence(v) => {
            let mut array = vec![];
            for yaml_value in v {
                array.push(yaml_to_json_value(key, yaml_value)?);
            }
            JSONValue::Array(array)
        }
        YamlValue::Mapping(v) => {
            let mut map = JsonMap::new();

            for (yaml_key, yaml_value) in v {
                let nested_key = parse_yaml_key(yaml_key)?;
                let value =
                    yaml_to_json_value(format!("{}.{}", key, nested_key).as_str(), yaml_value)?;
                map.insert(nested_key, value);
            }

            JSONValue::Object(map)
        }
    };

    Ok(json_value)
}

fn parse_yaml_key(yaml: YamlValue) -> Result<String, String> {
    match yaml {
        YamlValue::String(v) => Ok(v),
        v => Err(format!(
            "invalid key `{:?}`: only string keys are allowed",
            v
        )),
    }
}
#[cfg(test)]
mod tests {
    use crate::config::metadata::{parse_endpoint_metadata_from_yaml, yaml_to_json_value};
    use std::collections::HashSet;

    #[test]
    fn yaml_data_types() {
        let yaml = "
one: two
three:
    four:
        - five
        - 6
    seven:
        eight: true
";
        let yaml_value = serde_yaml::from_str(yaml).unwrap();
        let expected_json = serde_json::json!({
            "one": "two",
            "three": {
                "four": ["five", 6.0],
                "seven": {
                    "eight": true
                }
            }
        });

        assert_eq!(yaml_to_json_value("k", yaml_value).unwrap(), expected_json);
    }

    #[test]
    fn yaml_parse_endpoint_metadata() {
        let yaml = "
user:
    key1: value1
quilkin.dev:
    endpoint.tokens:
        - MXg3aWp5Ng== #1x7ijy6
        - OGdqM3YyaQ== #8gj3v2i
";
        let yaml_value = serde_yaml::from_str(yaml).unwrap();
        let expected_user_metadata = serde_json::json!({
            "user": {
                "key1": "value1"
            }
        });

        let (user_metadata, tokens) = parse_endpoint_metadata_from_yaml(yaml_value).unwrap();
        assert_eq!(user_metadata, expected_user_metadata);
        assert_eq!(
            tokens,
            vec!["1x7ijy6".into(), "8gj3v2i".into()]
                .into_iter()
                .collect::<HashSet<_>>()
        );
    }

    #[test]
    fn yaml_parse_invalid_endpoint_metadata() {
        let not_a_list = "
quilkin.dev:
    endpoint.tokens: OGdqM3YyaQ==
";
        let not_a_string_value = "
quilkin.dev:
    endpoint.tokens:
        - OGdqM3YyaQ== #8gj3v2i
        - 300
";
        let not_a_base64_string = "
quilkin.dev:
    endpoint.tokens:
        - OGdqM3YyaQ== #8gj3v2i
        - 1x7ijy6
";
        for yaml in &[not_a_list, not_a_string_value, not_a_base64_string] {
            let yaml_value = serde_yaml::from_str(yaml).unwrap();
            assert!(parse_endpoint_metadata_from_yaml(yaml_value).is_err());
        }
    }
}
