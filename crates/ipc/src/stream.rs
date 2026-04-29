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
