//! Hex decoding for input read from files, database rows and the
//! network.

/// Decode a hex string into bytes. Either case is accepted.
///
/// The input is checked as bytes, never sliced as a `&str`, so
/// non-ASCII text returns `Err` instead of panicking on a character
/// boundary.
pub fn decode(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.is_ascii() {
        return Err("non-ASCII hex string".into());
    }
    let bytes = hex.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err("odd-length hex string".into());
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        if let [hi, lo] = *pair {
            out.push((nibble(hi)? << 4) | nibble(lo)?);
        }
    }
    Ok(out)
}

fn nibble(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(format!("invalid hex digit {:?}", char::from(c))),
    }
}

#[cfg(test)]
mod tests {
    use super::decode;

    #[test]
    fn decodes_both_cases() {
        assert_eq!(decode("00ff7Fa0").unwrap(), vec![0x00, 0xff, 0x7f, 0xa0]);
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn rejects_non_ascii() {
        // Four bytes, with a character spanning offsets 1..3.
        assert_eq!(decode("a\u{e9}a").unwrap_err(), "non-ASCII hex string");
    }

    #[test]
    fn rejects_odd_length_and_bad_digits() {
        assert!(decode("abc").is_err());
        assert!(decode("zz").is_err());
        assert!(decode("+f").is_err());
    }
}
