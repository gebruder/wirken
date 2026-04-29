//! Transport-agnostic stream trait used by IPC consumers.
//!
//! Defines the surface that the gateway and adapters program against
//! when they need a connected duplex stream with a peer-identity
//! check. The current production code paths still use concrete
//! `tokio::net::UnixStream`; this trait is the shape they will
//! migrate to in a later PR so the same call sites work over a
//! Windows named-pipe backend.
//!
//! The trait is defined now so the windows backend (next PR) and
//! the eventual production migration land against a stable public
//! surface, not one that grows methods later.

use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::IpcError;
use crate::principal::Principal;

/// A bidirectional IPC stream with a peer-identity check.
///
/// Implementations exist for `tokio::net::UnixStream` on unix and
/// (in a later PR) for `tokio::net::windows::named_pipe` types on
/// windows. Consumers that hold a `Box<dyn Stream + Send>` get the
/// same read/write/peer-identity API on either platform.
pub trait Stream: AsyncRead + AsyncWrite + Send + Unpin {
    /// Identity of the connected peer.
    ///
    /// On unix this is the EUID from `SO_PEERCRED` at the time the
    /// connection was accepted. On windows this will be the user
    /// SID from the named-pipe client token.
    fn peer_principal(&self) -> Result<Principal, IpcError>;
}

#[cfg(unix)]
impl Stream for tokio::net::UnixStream {
    fn peer_principal(&self) -> Result<Principal, IpcError> {
        let cred = self.peer_cred()?;
        Ok(Principal::Uid(cred.uid()))
    }
}

// Windows named-pipe Stream impls. The peer-SID extraction lands in
// the next PR alongside the orchestrator integration and the audit
// event for refused pushes; for now `peer_principal` returns an
// `Unsupported` IO error so the trait surface is complete and the
// crate compiles on windows.
#[cfg(windows)]
impl Stream for tokio::net::windows::named_pipe::NamedPipeServer {
    fn peer_principal(&self) -> Result<Principal, IpcError> {
        Err(IpcError::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "peer_principal not yet implemented for named-pipe server",
        )))
    }
}

#[cfg(windows)]
impl Stream for tokio::net::windows::named_pipe::NamedPipeClient {
    fn peer_principal(&self) -> Result<Principal, IpcError> {
        Err(IpcError::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "peer_principal not yet implemented for named-pipe client",
        )))
    }
}

/// Boxed [`Stream`] suitable for sending across tokio tasks.
pub type BoxStream = Box<dyn Stream + Send>;

/// Connected pair of in-process streams for tests.
///
/// Returns two trait objects that share a duplex pipe. On unix this
/// is backed by `UnixStream::pair()`. The windows impl will follow
/// when the named-pipe backend lands.
#[cfg(unix)]
pub fn test_pair() -> std::io::Result<(BoxStream, BoxStream)> {
    let (a, b) = tokio::net::UnixStream::pair()?;
    Ok((Box::new(a), Box::new(b)))
}
