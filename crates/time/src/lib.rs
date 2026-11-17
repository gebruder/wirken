//! UTC instants and the text forms Wirken writes.
//!
//! Every store and every audit row written before this crate existed
//! carries RFC 3339 text in one of three shapes. They are kept byte
//! for byte, so a row written now compares, sorts and parses the same
//! as a row written by an older build:
//!
//! - [`TimestampExt::to_rfc3339`]: zero, three, six or nine fractional
//!   digits, whichever is the shortest that loses nothing, and a
//!   `+00:00` offset. The form of SQLite columns and JSON views.
//! - [`TimestampExt::to_rfc3339_z`]: the same digits with a `Z`. The
//!   form of an instant inside a serialized record ([`serde_z`]).
//! - [`TimestampExt::to_rfc3339_secs_z`]: whole seconds and a `Z`.
//!
//! [`FOREVER`] is the instant a grant with no expiry carries. In text
//! it is [`FOREVER_TEXT`], a year past 9999 that older builds wrote for
//! the same meaning.

pub use jiff;
pub use jiff::{SignedDuration, Timestamp};

/// The expiry of a grant that does not expire.
pub const FOREVER: Timestamp = Timestamp::MAX;

/// [`FOREVER`] as records carry it, without the offset.
pub const FOREVER_TEXT: &str = "+262142-12-31T23:59:59.999999999";

/// The current instant.
pub fn now() -> Timestamp {
    Timestamp::now()
}

/// A duration of `n` days of 24 hours.
pub fn days(n: i64) -> SignedDuration {
    SignedDuration::from_hours(24 * n)
}

/// The instant `secs` seconds after the Unix epoch, when it is one
/// this crate can represent.
pub fn from_unix_secs(secs: i64) -> Option<Timestamp> {
    Timestamp::from_second(secs).ok()
}

/// Text that is not an RFC 3339 instant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "not an RFC 3339 timestamp: {}", self.0)
    }
}

impl std::error::Error for ParseError {}

/// Parse an RFC 3339 instant with any offset. The date and time must
/// be in the full `YYYY-MM-DDTHH:MM:SS` layout, so text a looser
/// reader would take (a missing seconds field, a bracketed zone name)
/// is refused here.
pub fn parse_rfc3339(s: &str) -> Result<Timestamp, ParseError> {
    if let Some("Z" | "+00:00") = s.strip_prefix(FOREVER_TEXT) {
        return Ok(FOREVER);
    }
    let b = s.as_bytes();
    let laid_out = b.len() >= 20
        && b[..4].iter().all(u8::is_ascii_digit)
        && b[4] == b'-'
        && b[7] == b'-'
        && matches!(b[10], b'T' | b't' | b' ')
        && b[13] == b':'
        && b[16] == b':'
        && !s.contains('[');
    if !laid_out {
        return Err(ParseError(s.to_string()));
    }
    s.parse::<Timestamp>()
        .map_err(|e| ParseError(format!("{s}: {e}")))
}

/// Whole seconds since the epoch, rounded down, and the nanoseconds
/// past them.
fn parts(ts: Timestamp) -> (i64, i32) {
    let nanos = ts.subsec_nanosecond();
    if nanos < 0 {
        (ts.as_second() - 1, nanos + 1_000_000_000)
    } else {
        (ts.as_second(), nanos)
    }
}

fn civil_seconds(secs: i64) -> String {
    match Timestamp::from_second(secs) {
        Ok(whole) => whole.strftime("%Y-%m-%dT%H:%M:%S").to_string(),
        Err(_) => FOREVER_TEXT[..FOREVER_TEXT.len() - 10].to_string(),
    }
}

fn civil(ts: Timestamp) -> String {
    if ts == FOREVER {
        return FOREVER_TEXT.to_string();
    }
    let (secs, nanos) = parts(ts);
    let mut out = civil_seconds(secs);
    if nanos == 0 {
        return out;
    }
    if nanos % 1_000_000 == 0 {
        out.push_str(&format!(".{:03}", nanos / 1_000_000));
    } else if nanos % 1_000 == 0 {
        out.push_str(&format!(".{:06}", nanos / 1_000));
    } else {
        out.push_str(&format!(".{nanos:09}"));
    }
    out
}

/// The text forms of an instant.
pub trait TimestampExt {
    /// `2026-01-02T03:04:05.678+00:00`.
    fn to_rfc3339(&self) -> String;
    /// `2026-01-02T03:04:05.678Z`.
    fn to_rfc3339_z(&self) -> String;
    /// `2026-01-02T03:04:05Z`.
    fn to_rfc3339_secs_z(&self) -> String;
}

impl TimestampExt for Timestamp {
    fn to_rfc3339(&self) -> String {
        format!("{}+00:00", civil(*self))
    }

    fn to_rfc3339_z(&self) -> String {
        format!("{}Z", civil(*self))
    }

    fn to_rfc3339_secs_z(&self) -> String {
        if *self == FOREVER {
            return format!("{}Z", &FOREVER_TEXT[..FOREVER_TEXT.len() - 10]);
        }
        format!("{}Z", civil_seconds(parts(*self).0))
    }
}

/// `#[serde(with = "wirken_time::serde_z")]` for an instant in a
/// serialized record.
pub mod serde_z {
    use super::{Timestamp, TimestampExt, parse_rfc3339};
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(ts: &Timestamp, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&ts.to_rfc3339_z())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Timestamp, D::Error> {
        let text = String::deserialize(d)?;
        parse_rfc3339(&text).map_err(D::Error::custom)
    }

    /// The same for an `Option<Timestamp>`.
    pub mod option {
        use super::super::{Timestamp, TimestampExt, parse_rfc3339};
        use serde::{Deserialize, Deserializer, Serializer, de::Error};

        pub fn serialize<S: Serializer>(ts: &Option<Timestamp>, s: S) -> Result<S::Ok, S::Error> {
            match ts {
                Some(ts) => s.serialize_some(&ts.to_rfc3339_z()),
                None => s.serialize_none(),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Timestamp>, D::Error> {
            let text = Option::<String>::deserialize(d)?;
            text.map(|t| parse_rfc3339(&t).map_err(D::Error::custom))
                .transpose()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: i64, nanos: i32) -> Timestamp {
        Timestamp::new(secs, nanos).unwrap()
    }

    /// The expected strings are what the previous time library printed
    /// for the same instants.
    #[test]
    fn the_text_forms_are_the_ones_stored_rows_carry() {
        let cases = [
            (at(1_700_000_000, 0), "2023-11-14T22:13:20"),
            (at(1_700_000_000, 250_000_000), "2023-11-14T22:13:20.250"),
            (at(1_700_000_000, 100_000), "2023-11-14T22:13:20.000100"),
            (
                at(1_700_000_000, 123_456_780),
                "2023-11-14T22:13:20.123456780",
            ),
            (at(1_700_000_000, 1), "2023-11-14T22:13:20.000000001"),
            (at(0, 0), "1970-01-01T00:00:00"),
            (at(-1, 500_000_000), "1969-12-31T23:59:59.500"),
        ];
        for (ts, civil) in cases {
            assert_eq!(ts.to_rfc3339(), format!("{civil}+00:00"));
            assert_eq!(ts.to_rfc3339_z(), format!("{civil}Z"));
            assert_eq!(parse_rfc3339(&ts.to_rfc3339()).unwrap(), ts);
            assert_eq!(parse_rfc3339(&ts.to_rfc3339_z()).unwrap(), ts);
        }
        assert_eq!(
            at(1_700_000_000, 999_999_999).to_rfc3339_secs_z(),
            "2023-11-14T22:13:20Z"
        );
    }

    #[test]
    fn an_offset_is_converted_and_loose_text_is_refused() {
        assert_eq!(
            parse_rfc3339("2026-03-25T12:30:00+02:00").unwrap(),
            parse_rfc3339("2026-03-25T10:30:00Z").unwrap()
        );
        for bad in [
            "",
            "2026-03-25",
            "2026-03-25T10:30Z",
            "2026-03-25T10:30:00",
            "2026-03-25T10:30:00Z[UTC]",
            "yesterday",
        ] {
            assert!(parse_rfc3339(bad).is_err(), "{bad}");
        }
    }

    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
    struct Record {
        #[serde(with = "serde_z")]
        at: Timestamp,
        #[serde(with = "serde_z::option", default)]
        due: Option<Timestamp>,
    }

    #[test]
    fn a_grant_with_no_expiry_reads_and_writes_as_older_builds_wrote_it() {
        let old = r#"{"at":"+262142-12-31T23:59:59.999999999Z","due":null}"#;
        let record: Record = serde_json::from_str(old).unwrap();
        assert_eq!(record.at, FOREVER);
        assert_eq!(serde_json::to_string(&record).unwrap(), old);
        assert_eq!(
            FOREVER.to_rfc3339(),
            "+262142-12-31T23:59:59.999999999+00:00"
        );
        assert_eq!(parse_rfc3339(&FOREVER.to_rfc3339()).unwrap(), FOREVER);
    }

    #[test]
    fn a_record_round_trips_with_and_without_the_optional_instant() {
        let record = Record {
            at: at(1_700_000_000, 250_000_000),
            due: Some(at(1_700_000_100, 0)),
        };
        let text = serde_json::to_string(&record).unwrap();
        assert_eq!(
            text,
            r#"{"at":"2023-11-14T22:13:20.250Z","due":"2023-11-14T22:15:00Z"}"#
        );
        assert_eq!(serde_json::from_str::<Record>(&text).unwrap(), record);
        let bare: Record = serde_json::from_str(r#"{"at":"2023-11-14T22:13:20Z"}"#).unwrap();
        assert_eq!(bare.due, None);
    }
}
