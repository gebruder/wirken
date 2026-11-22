//! The loopback relay a contained MCP server with an injected
//! credential is started under.
//!
//! Some servers send plain HTTP only to a loopback address. The relay
//! gives such a server one inside its own container: it listens on
//! loopback, runs the server as its child, and copies every connection
//! to the sidecar's injected-route listener. It holds no secret and no
//! rule, and reads nothing it copies. The server's stdin, stdout and
//! stderr are the relay's own, inherited, so the JSON-RPC stream never
//! passes through this process.

use std::ffi::OsString;
use std::net::SocketAddr;

use tokio::net::{TcpListener, TcpStream};

/// The exit status reported for a child a signal ended, as a shell
/// reports it.
fn signal_status(signal: i32) -> i32 {
    128 + signal
}

/// Listen on `listen`, run `command`, and copy each connection to
/// `to` until the command exits. Returns the command's exit status.
///
/// `listen` must be a loopback address: the relay is reachable only
/// from inside the container it runs in. SIGTERM and SIGINT are passed
/// to the command, since the relay is the container's first process
/// and the runtime signals that one.
pub async fn run(
    listen: SocketAddr,
    to: SocketAddr,
    command: Vec<OsString>,
) -> std::io::Result<i32> {
    if !listen.ip().is_loopback() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("the relay listens on loopback only, not {listen}"),
        ));
    }
    // Listening before the command starts, so its first request finds
    // the relay there.
    serve(TcpListener::bind(listen).await?, to, command).await
}

/// [`run`] on a listener that is already bound.
async fn serve(
    listener: TcpListener,
    to: SocketAddr,
    command: Vec<OsString>,
) -> std::io::Result<i32> {
    use std::os::unix::process::ExitStatusExt;
    use tokio::signal::unix::{SignalKind, signal};

    let (program, args) = command.split_first().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "no command to run")
    })?;
    let mut child = tokio::process::Command::new(program)
        .args(args)
        .kill_on_drop(true)
        .spawn()?;
    let pid = child.id().and_then(|p| libc::pid_t::try_from(p).ok());
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    let pass = |sig: libc::c_int| {
        if let Some(pid) = pid {
            // SAFETY: kill(2) on a child this process spawned and has
            // not yet waited for, with a valid signal number.
            unsafe {
                libc::kill(pid, sig);
            }
        }
    };
    loop {
        tokio::select! {
            status = child.wait() => {
                let status = status?;
                return Ok(status
                    .code()
                    .or_else(|| status.signal().map(signal_status))
                    .unwrap_or(1));
            }
            _ = term.recv() => pass(libc::SIGTERM),
            _ = int.recv() => pass(libc::SIGINT),
            accepted = listener.accept() => {
                if let Ok((client, _)) = accepted {
                    tokio::spawn(async move {
                        if let Err(e) = copy(client, to).await {
                            tracing::debug!("relay connection ended: {e}");
                        }
                    });
                }
            }
        }
    }
}

async fn copy(mut client: TcpStream, to: SocketAddr) -> std::io::Result<()> {
    let mut upstream = TcpStream::connect(to).await?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream)
        .await
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn os(parts: &[&str]) -> Vec<OsString> {
        parts.iter().map(OsString::from).collect()
    }

    async fn loopback() -> (TcpListener, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        (listener, addr)
    }

    /// A connection to the relay's loopback port reaches the address it
    /// was started with, bytes unchanged both ways, and the relay ends
    /// with its command's exit status.
    #[tokio::test]
    async fn a_connection_is_copied_to_the_target_and_the_command_status_is_returned() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let to = target.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = target.accept().await.unwrap();
            let mut buf = [0u8; 4];
            s.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            s.write_all(b"pong").await.unwrap();
        });
        let (listener, listen) = loopback().await;
        // The command holds the relay up long enough for one exchange.
        let relay = tokio::spawn(serve(listener, to, os(&["sh", "-c", "sleep 2; exit 7"])));

        let mut client = TcpStream::connect(listen).await.unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
        assert_eq!(relay.await.unwrap().unwrap(), 7);
    }

    #[tokio::test]
    async fn a_listen_address_off_loopback_is_refused() {
        let err = run(
            "0.0.0.0:3180".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
            os(&["true"]),
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn a_signalled_command_reports_the_shell_status() {
        let (listener, listen) = loopback().await;
        let status = serve(listener, listen, os(&["sh", "-c", "kill -TERM $$"]))
            .await
            .unwrap();
        assert_eq!(status, 128 + libc::SIGTERM);
    }
}
