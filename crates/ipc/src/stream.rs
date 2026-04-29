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

// Windows named-pipe Stream impls. The server-side peer-SID
// extraction is the load-bearing path for the orchestrator-push
// peer-credential check (see crates/cli/src/commands/run.rs); the
// client-side method stays a stub for now since no caller asks
// "who is the server" today.
#[cfg(windows)]
impl Stream for tokio::net::windows::named_pipe::NamedPipeServer {
    fn peer_principal(&self) -> Result<Principal, IpcError> {
        use std::os::windows::io::AsRawHandle;
        win::peer_sid_from_named_pipe(self.as_raw_handle() as isize, win::PipeEnd::Server)
    }
}

#[cfg(windows)]
impl Stream for tokio::net::windows::named_pipe::NamedPipeClient {
    fn peer_principal(&self) -> Result<Principal, IpcError> {
        Err(IpcError::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "peer_principal on the client side is not yet implemented",
        )))
    }
}

#[cfg(windows)]
mod win {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
    use windows_sys::Win32::System::Pipes::{
        GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    use windows_sys::core::PWSTR;

    use crate::error::IpcError;
    use crate::principal::Principal;

    pub(super) enum PipeEnd {
        Server,
        #[allow(dead_code)]
        Client,
    }

    /// RAII guard that closes a Win32 HANDLE on drop. Only used for
    /// handles we own; the pipe handle itself is owned by tokio and
    /// must not be closed here.
    struct OwnedHandle(HANDLE);
    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if self.0 != 0 {
                // SAFETY: handles in OwnedHandle are returned by
                // OpenProcess / OpenProcessToken and are documented
                // to be released with CloseHandle.
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    fn last_error_io(context: &str) -> IpcError {
        IpcError::Io(std::io::Error::other(format!(
            "{context}: {}",
            std::io::Error::last_os_error()
        )))
    }

    /// Look up the user SID for the process at the other end of a
    /// named-pipe handle.
    ///
    /// `pipe_handle` must be the raw HANDLE owned by tokio's
    /// `NamedPipeServer` or `NamedPipeClient`; we never close it
    /// here. `end` selects which side of the pipe to query the peer
    /// PID from.
    pub(super) fn peer_sid_from_named_pipe(
        pipe_handle: HANDLE,
        end: PipeEnd,
    ) -> Result<Principal, IpcError> {
        // SAFETY: each Win32 call below has its preconditions
        // documented inline. The handles we open are wrapped in
        // OwnedHandle so they're closed on every exit path.
        unsafe {
            // 1. Get the peer's process ID from the pipe handle.
            let mut pid: u32 = 0;
            let ok = match end {
                PipeEnd::Server => GetNamedPipeClientProcessId(pipe_handle, &mut pid),
                PipeEnd::Client => GetNamedPipeServerProcessId(pipe_handle, &mut pid),
            };
            if ok == 0 {
                return Err(last_error_io("GetNamedPipe*ProcessId"));
            }

            // 2. Open the peer process with limited query rights.
            // PROCESS_QUERY_LIMITED_INFORMATION is the minimum
            // privilege needed to call OpenProcessToken on the
            // returned handle for token-info query.
            let raw_proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if raw_proc == 0 {
                return Err(last_error_io("OpenProcess"));
            }
            let proc_handle = OwnedHandle(raw_proc);

            // 3. Open the process token for query.
            let mut raw_token: HANDLE = 0;
            if OpenProcessToken(proc_handle.0, TOKEN_QUERY, &mut raw_token) == 0 {
                return Err(last_error_io("OpenProcessToken"));
            }
            let token = OwnedHandle(raw_token);

            // 4. Probe the size of the TOKEN_USER struct. The first
            // GetTokenInformation call always fails with
            // ERROR_INSUFFICIENT_BUFFER and writes the needed size.
            let mut size: u32 = 0;
            GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut size);
            if size == 0 {
                return Err(last_error_io("GetTokenInformation (size probe)"));
            }

            // 5. Allocate and fetch.
            let mut buffer: Vec<u8> = vec![0u8; size as usize];
            if GetTokenInformation(
                token.0,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                size,
                &mut size,
            ) == 0
            {
                return Err(last_error_io("GetTokenInformation"));
            }

            let token_user = buffer.as_ptr() as *const TOKEN_USER;
            let sid_ptr = (*token_user).User.Sid;

            // 6. Convert the binary SID to its `S-1-...` string form.
            // ConvertSidToStringSidW allocates the result via
            // LocalAlloc; we must release it with LocalFree.
            let mut sid_string_ptr: PWSTR = std::ptr::null_mut();
            if ConvertSidToStringSidW(sid_ptr, &mut sid_string_ptr) == 0 {
                return Err(last_error_io("ConvertSidToStringSidW"));
            }

            let sid_str = wide_to_string(sid_string_ptr);
            LocalFree(sid_string_ptr as isize as HLOCAL);

            Ok(Principal::Sid(sid_str))
        }
    }

    /// Materialize a NUL-terminated wide string into a Rust `String`.
    ///
    /// SAFETY: `ptr` must point to a NUL-terminated UTF-16 string
    /// owned by the caller for at least the duration of this call.
    unsafe fn wide_to_string(ptr: *const u16) -> String {
        let mut len = 0usize;
        // SAFETY: documented as NUL-terminated.
        while unsafe { *ptr.add(len) } != 0 {
            len += 1;
        }
        // SAFETY: len is the count of u16 cells before the NUL.
        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
        String::from_utf16_lossy(slice)
    }
}

/// Boxed [`Stream`] suitable for sending across tokio tasks.
pub type BoxStream = Box<dyn Stream + Send>;

/// Server-side accept loop for IPC listeners.
///
/// The unix impl wraps `tokio::net::UnixListener::accept()`. The
/// windows impl wraps the named-pipe accept dance: a server
/// instance is created for each pending connection, `connect()`
/// awaits the client, and a fresh instance is created for the next
/// accept. Both impls return a [`BoxStream`] so consumers don't
/// need to know which platform they're on.
#[async_trait::async_trait]
pub trait Listener: Send {
    async fn accept(&mut self) -> Result<BoxStream, IpcError>;
}

#[cfg(unix)]
#[async_trait::async_trait]
impl Listener for tokio::net::UnixListener {
    async fn accept(&mut self) -> Result<BoxStream, IpcError> {
        let (stream, _addr) = tokio::net::UnixListener::accept(self).await?;
        Ok(Box::new(stream))
    }
}

/// Bind an IPC listener at `path`.
///
/// On unix `path` is a filesystem path used as a unix-domain
/// socket. On windows `path` is mapped to a named-pipe name under
/// `\\.\pipe\` derived from the path's last two components plus a
/// hash of the full path; this keeps the "one listener per data
/// dir" property without the operator having to track windows
/// pipe-namespace details.
pub fn bind(path: &std::path::Path) -> Result<Box<dyn Listener>, IpcError> {
    #[cfg(unix)]
    {
        let inner = tokio::net::UnixListener::bind(path)?;
        Ok(Box::new(inner))
    }
    #[cfg(windows)]
    {
        Ok(Box::new(named_pipe_listener::NamedPipeListener::bind(
            path,
        )?))
    }
}

/// Connect to an IPC listener at `path`. The path mapping is the
/// same as [`bind`].
pub async fn connect(path: &std::path::Path) -> Result<BoxStream, IpcError> {
    #[cfg(unix)]
    {
        let s = tokio::net::UnixStream::connect(path).await?;
        Ok(Box::new(s))
    }
    #[cfg(windows)]
    {
        let pipe = named_pipe_listener::pipe_name_for(path);
        let client = tokio::net::windows::named_pipe::ClientOptions::new().open(pipe)?;
        Ok(Box::new(client))
    }
}

#[cfg(windows)]
mod named_pipe_listener {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::path::Path;

    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

    use super::{BoxStream, Listener};
    use crate::error::IpcError;

    /// Map a unix-style path to a windows pipe name. The last
    /// segment of the path becomes a human-readable suffix; a
    /// 16-hex-digit hash of the full path makes the name unique
    /// across data dirs on the same machine.
    pub(super) fn pipe_name_for(path: &Path) -> String {
        let mut hasher = DefaultHasher::new();
        path.hash(&mut hasher);
        let hash = hasher.finish();
        let label = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "wirken".into())
            .replace(['.', '/', '\\'], "-");
        format!(r"\\.\pipe\wirken-{label}-{hash:016x}")
    }

    /// Owns the next pending named-pipe server instance and re-arms
    /// after each successful accept.
    pub struct NamedPipeListener {
        path: String,
        pending: Option<NamedPipeServer>,
    }

    impl NamedPipeListener {
        pub fn bind(path: &Path) -> Result<Self, IpcError> {
            let pipe_path = pipe_name_for(path);
            let pending = ServerOptions::new()
                .first_pipe_instance(true)
                .create(&pipe_path)?;
            Ok(Self {
                path: pipe_path,
                pending: Some(pending),
            })
        }
    }

    #[async_trait::async_trait]
    impl Listener for NamedPipeListener {
        async fn accept(&mut self) -> Result<BoxStream, IpcError> {
            let server = self.pending.take().ok_or_else(|| {
                IpcError::Io(std::io::Error::other(
                    "NamedPipeListener has no pending instance",
                ))
            })?;
            server.connect().await?;
            // Pre-arm the next instance so the next accept() can
            // start awaiting a client immediately.
            self.pending = Some(ServerOptions::new().create(&self.path)?);
            Ok(Box::new(server))
        }
    }
}

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
