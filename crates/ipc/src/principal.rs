//! Cross-platform peer-identity type for IPC connections.
//!
//! `Principal` is the type returned by [`crate::Stream::peer_principal`]
//! and the type carried in audit events that record peer-credential
//! checks. The wire form is a tagged string (`uid:1000` on unix,
//! `sid:S-1-5-21-...` on windows) so audit consumers can parse a
//! single field without knowing what platform produced the event.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// Identity of the peer on the other end of an IPC connection.
///
/// The variants correspond to the native peer-credential primitives
/// on each platform. `Display` produces the tagged-string wire form
/// (`uid:1000`, `sid:S-1-5-...`); `FromStr` parses it back.
/// Serde goes through the string form so the on-disk and on-wire
/// representation matches `Display`, not the Rust enum shape.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Principal {
    /// POSIX user id, from `SO_PEERCRED` on a connected unix socket.
    Uid(u32),
    /// Windows security identifier, from the named-pipe client token.
    Sid(String),
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uid(uid) => write!(f, "uid:{uid}"),
            Self::Sid(sid) => write!(f, "sid:{sid}"),
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("invalid principal '{0}'")]
pub struct ParsePrincipalError(pub String);

impl FromStr for Principal {
    type Err = ParsePrincipalError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(rest) = s.strip_prefix("uid:") {
            rest.parse::<u32>()
                .map(Self::Uid)
                .map_err(|_| ParsePrincipalError(s.to_string()))
        } else if let Some(rest) = s.strip_prefix("sid:") {
            if rest.is_empty() {
                Err(ParsePrincipalError(s.to_string()))
            } else {
                Ok(Self::Sid(rest.to_string()))
            }
        } else {
            Err(ParsePrincipalError(s.to_string()))
        }
    }
}

impl Serialize for Principal {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Principal {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}
