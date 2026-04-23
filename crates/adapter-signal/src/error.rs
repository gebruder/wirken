use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignalError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("ipc error: {0}")]
    Ipc(#[from] wirken_ipc::IpcError),

    #[error("handshake error: {0}")]
    Handshake(#[from] wirken_ipc::HandshakeError),

    #[error("signal-cli error: {0}")]
    Signal(String),

    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),

    /// signal-cli closed the JSON-RPC stream, or the oneshot sender for an
    /// in-flight request was dropped (typically because the connection
    /// dropped mid-RPC and the pending map was cleared).
    #[error("signal-cli connection closed")]
    ConnectionClosed,

    /// RPC response did not arrive within the adapter's timeout window.
    /// Rare in healthy operation; usually means signal-cli is wedged.
    #[error("signal-cli RPC timeout ({method})")]
    Timeout { method: String },

    /// `subscribeReceive` did not return a numeric result. signal-cli's
    /// contract says it must; this surfaces a daemon build mismatch or
    /// protocol drift rather than silently running with no subscription.
    #[error("subscribeReceive did not return a subscription id")]
    BadSubscribeResponse,

    /// Configured endpoint is an HTTP URL. The adapter moved to
    /// `--socket` JSON-RPC; surface a clear migration message at startup
    /// rather than looping in reconnect with a cryptic UnixStream error.
    #[error(
        "signal endpoint is an HTTP URL ('{0}'); the adapter now speaks \
         JSON-RPC over a Unix socket. Run signal-cli with `daemon --socket \
         /tmp/signal-cli.sock` and set the endpoint to the socket path \
         (e.g. /tmp/signal-cli.sock or unix:///tmp/signal-cli.sock). See \
         docs/channels/signal.md"
    )]
    HttpEndpointRejected(String),
}
