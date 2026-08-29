//! Reading an assistant data-export archive, under caps.
//!
//! # Path traversal is removed, not filtered
//!
//! This module never writes a file. There is no destination path
//! parameter anywhere in its API: members are opened by name and read
//! into the caller's buffer or streamed through a parser. An entry
//! named `../../etc/passwd` is a string that names a member, and
//! reading it produces bytes, not a write outside the archive.
//!
//! Filtering entry names would be the weaker design, because it makes
//! safety depend on the filter catching every encoding of an escape.
//! Not having a write path makes the question not arise. If storing
//! attachments to disk is ever added, that decision reopens this and
//! needs its own containment.
//!
//! # Caps
//!
//! Two layers, because the first one trusts the archive.
//!
//! The central directory declares each member's compressed and
//! uncompressed size. [`Archive::open`] checks the declared numbers
//! against the caps and refuses before decompressing
//! anything, which is what makes an oversized or bomb archive cheap to
//! turn away.
//!
//! Those declarations are attacker-influenced. A member whose header
//! understates its size would pass the first check and then expand
//! past the cap while streaming, so [`Archive::read_member`] also caps
//! the bytes it will actually produce and returns an error rather than
//! a short read when the cap is reached. A truncating reader would
//! hand the parser a prefix of a hostile member and look like a
//! well-formed short file.

use std::io::{self, Read};
use std::path::Path;

use crate::error::GatewayError;

/// Structural bounds an archive must satisfy before anything is read.
///
/// Private, and there is no way to vary it from outside this module.
/// The caps are constants rather than configuration: an operator who
/// can raise the bomb ratio to get a stubborn archive to import has
/// turned the control off at the moment it was doing its job, and the
/// setting would outlive the archive that prompted it. A cap that is
/// genuinely wrong for real archives is a code change with a reason
/// attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Limits {
    /// Entries in the central directory.
    max_members: usize,
    /// Declared and actual uncompressed bytes for any one member.
    max_member_bytes: u64,
    /// Declared uncompressed bytes summed across every member.
    max_total_bytes: u64,
    /// Uncompressed over compressed, per member. A zip bomb is
    /// distinguished from ordinary text by this ratio and by nothing
    /// else cheap.
    max_compression_ratio: u64,
}

/// Sized against real export archives with headroom, not against what
/// SQLite or the filesystem could survive. The conversation file is
/// the large member and compresses around five to one; these bounds
/// leave room for an archive well beyond that while still refusing
/// something built to expand.
const LIMITS: Limits = Limits {
    max_members: 10_000,
    max_member_bytes: 2 << 30,
    max_total_bytes: 8 << 30,
    max_compression_ratio: 100,
};

/// An opened export archive.
pub struct Archive {
    zip: zip::ZipArchive<std::fs::File>,
    limits: Limits,
}

impl std::fmt::Debug for Archive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Archive")
            .field("members", &self.zip.len())
            .field("limits", &self.limits)
            .finish()
    }
}

impl Archive {
    /// Open an archive and refuse it if the central directory declares
    /// a shape outside the limits.
    ///
    /// Nothing is decompressed here. Every check reads declared sizes,
    /// so a hostile archive is turned away before it costs anything.
    pub fn open(path: &Path) -> Result<Self, GatewayError> {
        Self::open_with(path, LIMITS)
    }

    /// The same open, against caps a test can shrink so a cap is
    /// exercised by a fixture rather than by a multi-gigabyte file.
    /// Not reachable outside this module's tests.
    #[cfg(test)]
    fn open_with_limits(path: &Path, limits: Limits) -> Result<Self, GatewayError> {
        Self::open_with(path, limits)
    }

    fn open_with(path: &Path, limits: Limits) -> Result<Self, GatewayError> {
        let file = std::fs::File::open(path)?;
        let zip = zip::ZipArchive::new(file)
            .map_err(|e| GatewayError::ArchiveRefused(format!("not a readable zip: {e}")))?;

        if zip.len() > limits.max_members {
            return Err(GatewayError::ArchiveRefused(format!(
                "archive declares {} members, over the cap of {}",
                zip.len(),
                limits.max_members
            )));
        }

        let mut zip = zip;
        let mut total: u64 = 0;
        for idx in 0..zip.len() {
            let entry = zip
                .by_index_raw(idx)
                .map_err(|e| GatewayError::ArchiveRefused(format!("unreadable member: {e}")))?;
            if entry.is_dir() {
                continue;
            }
            let declared = entry.size();
            let compressed = entry.compressed_size();
            let name = entry.name().to_string();
            drop(entry);

            if declared > limits.max_member_bytes {
                return Err(GatewayError::ArchiveRefused(format!(
                    "member '{name}' declares {declared} bytes, over the per-member cap of {}",
                    limits.max_member_bytes
                )));
            }
            // Ratio is only meaningful once a member is big enough
            // that the archive's own framing is not the dominant term.
            if compressed > 0 && declared / compressed.max(1) > limits.max_compression_ratio {
                return Err(GatewayError::ArchiveRefused(format!(
                    "member '{name}' expands {}x, over the ratio cap of {}",
                    declared / compressed.max(1),
                    limits.max_compression_ratio
                )));
            }
            total = total.saturating_add(declared);
            if total > limits.max_total_bytes {
                return Err(GatewayError::ArchiveRefused(format!(
                    "archive declares {total} uncompressed bytes in total by member '{name}', \
                     over the total cap of {}",
                    limits.max_total_bytes
                )));
            }
        }

        Ok(Self { zip, limits })
    }

    /// Whether a member of this name is present.
    pub fn has_member(&mut self, name: &str) -> bool {
        self.zip.by_name(name).is_ok()
    }

    /// Stream one member, capped at the per-member byte limit.
    ///
    /// The returned reader errors rather than ending early when the cap
    /// is reached, so a member whose header understated its size cannot
    /// be handed to a parser as a well-formed prefix.
    pub fn read_member(&mut self, name: &str) -> Result<CappedReader<'_>, GatewayError> {
        let cap = self.limits.max_member_bytes;
        let entry = self
            .zip
            .by_name(name)
            .map_err(|e| GatewayError::ArchiveRefused(format!("member '{name}': {e}")))?;
        Ok(CappedReader {
            inner: entry,
            remaining: cap,
            name: name.to_string(),
        })
    }
}

/// A member reader that refuses to produce more than its cap.
pub struct CappedReader<'a> {
    inner: zip::read::ZipFile<'a, std::fs::File>,
    remaining: u64,
    name: String,
}

impl Read for CappedReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            // Probe for a byte past the cap. Ending quietly here would
            // be indistinguishable from a member that really ended.
            let mut probe = [0u8; 1];
            return match self.inner.read(&mut probe)? {
                0 => Ok(0),
                _ => Err(io::Error::other(format!(
                    "member '{}' expanded past its cap",
                    self.name
                ))),
            };
        }
        let want = buf.len().min(self.remaining as usize);
        let n = self.inner.read(&mut buf[..want])?;
        self.remaining -= n as u64;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn write_zip(dir: &Path, name: &str, members: &[(&str, &[u8])]) -> std::path::PathBuf {
        let path = dir.join(name);
        let file = std::fs::File::create(&path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let opts: zip::write::FileOptions<'_, ()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for (member, body) in members {
            zip.start_file(*member, opts).unwrap();
            zip.write_all(body).unwrap();
        }
        zip.finish().unwrap();
        path
    }

    #[test]
    fn a_plain_archive_opens_and_streams_its_member() {
        let tmp = TempDir::new().unwrap();
        let path = write_zip(tmp.path(), "a.zip", &[("conversations.json", b"[]")]);
        let mut archive = Archive::open(&path).unwrap();
        assert!(archive.has_member("conversations.json"));
        let mut body = String::new();
        archive
            .read_member("conversations.json")
            .unwrap()
            .read_to_string(&mut body)
            .unwrap();
        assert_eq!(body, "[]");
    }

    #[test]
    fn a_traversal_named_entry_writes_nothing_outside_the_archive() {
        let tmp = TempDir::new().unwrap();
        let escape = "../../../../../../tmp/wirken-traversal-probe";
        let path = write_zip(tmp.path(), "a.zip", &[(escape, b"payload")]);
        let mut archive = Archive::open(&path).unwrap();
        // The name is data. Reading it yields bytes; there is no
        // destination parameter, so nothing is written anywhere.
        let mut body = String::new();
        archive
            .read_member(escape)
            .unwrap()
            .read_to_string(&mut body)
            .unwrap();
        assert_eq!(body, "payload");
        assert!(!Path::new("/tmp/wirken-traversal-probe").exists());
    }

    #[test]
    fn too_many_members_is_refused_before_anything_is_read() {
        let tmp = TempDir::new().unwrap();
        let bodies: Vec<(String, Vec<u8>)> = (0..5)
            .map(|i| (format!("m{i}.json"), b"[]".to_vec()))
            .collect();
        let refs: Vec<(&str, &[u8])> = bodies
            .iter()
            .map(|(n, b)| (n.as_str(), b.as_slice()))
            .collect();
        let path = write_zip(tmp.path(), "a.zip", &refs);
        let limits = Limits {
            max_members: 2,
            ..LIMITS
        };
        let err = Archive::open_with_limits(&path, limits)
            .unwrap_err()
            .to_string();
        assert_refusal_names_cap_observed_and_limit(&err, "members", "5", "2");
    }

    #[test]
    fn an_oversized_member_is_refused_on_its_declared_size() {
        let tmp = TempDir::new().unwrap();
        let path = write_zip(tmp.path(), "a.zip", &[("big.json", &vec![b'x'; 4096])]);
        let limits = Limits {
            max_member_bytes: 1024,
            max_compression_ratio: u64::MAX,
            ..LIMITS
        };
        let err = Archive::open_with_limits(&path, limits)
            .unwrap_err()
            .to_string();
        assert_refusal_names_cap_observed_and_limit(&err, "per-member cap", "4096", "1024");
    }

    #[test]
    fn a_bomb_ratio_is_refused() {
        let tmp = TempDir::new().unwrap();
        // Highly compressible: a long run of one byte.
        let path = write_zip(tmp.path(), "a.zip", &[("bomb.json", &vec![0u8; 1 << 20])]);
        let limits = Limits {
            max_compression_ratio: 10,
            ..LIMITS
        };
        let err = Archive::open_with_limits(&path, limits)
            .unwrap_err()
            .to_string();
        // The observed ratio is whatever deflate achieved, so assert
        // its shape rather than a brittle exact figure.
        assert!(err.contains("ratio cap"), "names the cap: {err}");
        assert!(err.contains("expands"), "names the observed ratio: {err}");
        assert!(err.contains("10"), "names the limit: {err}");
    }

    #[test]
    fn a_total_size_over_the_cap_is_refused() {
        let tmp = TempDir::new().unwrap();
        let a = vec![b'a'; 2048];
        let b = vec![b'b'; 2048];
        let path = write_zip(tmp.path(), "a.zip", &[("a.json", &a), ("b.json", &b)]);
        let limits = Limits {
            max_total_bytes: 3000,
            max_compression_ratio: u64::MAX,
            ..LIMITS
        };
        let err = Archive::open_with_limits(&path, limits)
            .unwrap_err()
            .to_string();
        assert_refusal_names_cap_observed_and_limit(&err, "total cap", "4096", "3000");
    }

    /// Every refusal names the cap it tripped, the value observed, and
    /// the limit. An operator reading a refusal should not have to open
    /// the source to learn which of the four turned the archive away or
    /// by how much.
    fn assert_refusal_names_cap_observed_and_limit(
        err: &str,
        cap: &str,
        observed: &str,
        limit: &str,
    ) {
        assert!(err.contains(cap), "names the cap: {err}");
        assert!(err.contains(observed), "names the observed value: {err}");
        assert!(err.contains(limit), "names the limit: {err}");
    }

    /// Bytes that do not compress, so a fixture can be large without
    /// tripping the ratio cap that guards against bombs.
    fn incompressible(len: usize) -> Vec<u8> {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state & 0xff) as u8
            })
            .collect()
    }

    #[test]
    fn the_streaming_cap_errors_rather_than_ending_early() {
        let tmp = TempDir::new().unwrap();
        let path = write_zip(tmp.path(), "a.zip", &[("m.json", &incompressible(4096))]);
        // Open with a generous declared-size cap, then stream with a
        // reader whose cap is smaller, standing in for a member whose
        // header understated its size.
        let mut archive = Archive::open(&path).unwrap();
        let mut reader = archive.read_member("m.json").unwrap();
        reader.remaining = 16;
        let mut sink = Vec::new();
        let err = reader.read_to_end(&mut sink).unwrap_err();
        assert!(err.to_string().contains("expanded past its cap"), "{err}");
    }

    #[test]
    fn a_file_that_is_not_a_zip_is_refused() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("not.zip");
        std::fs::write(&path, b"this is not a zip archive").unwrap();
        let err = Archive::open(&path).unwrap_err().to_string();
        assert!(err.contains("not a readable zip"), "{err}");
    }
}
