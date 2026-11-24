//! Sérialisation Serde des octets en Base64 standard.
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Deserializer, Serializer};

pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&STANDARD.encode(bytes))
}

pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let s = String::deserialize(d)?;
    STANDARD.decode(s.as_bytes()).map_err(serde::de::Error::custom)
}

pub mod option {
    use super::*;

    pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(b) => s.serialize_some(&STANDARD.encode(b)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let o = Option::<String>::deserialize(d)?;
        o.map(|s| STANDARD.decode(s.as_bytes()).map_err(serde::de::Error::custom)).transpose()
    }
}

pub mod vec {
    use super::*;
    use serde::ser::SerializeSeq;

    pub fn serialize<S: Serializer>(v: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(v.len()))?;
        for b in v {
            seq.serialize_element(&STANDARD.encode(b))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
        let v = Vec::<String>::deserialize(d)?;
        v.into_iter().map(|s| STANDARD.decode(s.as_bytes()).map_err(serde::de::Error::custom)).collect()
    }
}
