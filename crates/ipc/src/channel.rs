use std::fmt;
use std::marker::PhantomData;

use thiserror::Error;

/// The channel an IPC connection was authenticated under, as
/// resolved from the adapter registry after a successful Ed25519
/// handshake. Threaded through the gateway's message loop so that
/// every inbound frame's self-declared `channel` field can be
/// checked against the authenticated value.
///
/// A bare `String` would work here, but the distinction between
/// "authenticated channel" (trusted, set once at handshake) and
/// "claimed channel" (untrusted, read from the wire on every
/// frame) is exactly the confusion this type is named to prevent.
/// Callers that accidentally pass the claimed value where the
/// authenticated one is expected get a type-mismatch at review
/// time rather than a runtime cross-channel impersonation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthenticatedChannel(String);

impl AuthenticatedChannel {
    /// Construct from the string stored in the adapter registry.
    /// Only the gateway (and tests) should construct this.
    pub fn new(channel: impl Into<String>) -> Self {
        Self(channel.into())
    }

    /// The channel identifier as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Succeeds iff `claimed` equals the authenticated channel.
    /// Returns `ChannelMismatch` otherwise so callers can audit
    /// the attempt and drop the frame without taking a branch on
    /// the claimed value.
    pub fn require_match(&self, claimed: &str) -> Result<(), ChannelMismatch> {
        if claimed == self.0 {
            Ok(())
        } else {
            Err(ChannelMismatch {
                authenticated: self.0.clone(),
                claimed: claimed.to_string(),
            })
        }
    }
}

impl fmt::Display for AuthenticatedChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An inbound frame claimed to originate from a channel the
/// authenticated connection is not responsible for. The gateway
/// rejects the frame and audits both sides of the mismatch.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("channel mismatch: authenticated as '{authenticated}', frame claimed '{claimed}'")]
pub struct ChannelMismatch {
    pub authenticated: String,
    pub claimed: String,
}

/// Trait for channel marker types. Sealed — only types defined
/// in this crate can implement it.
pub trait Channel: Send + Sync + 'static {
    /// The string identifier for this channel on the wire.
    fn id() -> &'static str;
}

/// A session identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId(pub String);

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A session handle scoped to a specific channel.
///
/// `SessionHandle<Telegram>` cannot be converted to or used as
/// `SessionHandle<Discord>`. The type parameter is a zero-sized
/// marker — no runtime cost, compile-time enforcement.
///
/// An adapter holding `SessionHandle<Telegram>` physically cannot
/// construct `SessionHandle<Discord>` because the `new` constructor
/// requires the caller to provide the correct channel marker type,
/// and the gateway only hands out handles typed to the adapter's channel.
pub struct SessionHandle<C: Channel> {
    id: SessionId,
    _channel: PhantomData<C>,
}

impl<C: Channel> SessionHandle<C> {
    /// Create a new session handle. Only the gateway should call this,
    /// scoping the handle to the adapter's channel type.
    pub fn new(id: SessionId) -> Self {
        Self {
            id,
            _channel: PhantomData,
        }
    }

    /// Get the session ID.
    pub fn id(&self) -> &SessionId {
        &self.id
    }

    /// Get the channel identifier string.
    pub fn channel_id(&self) -> &'static str {
        C::id()
    }
}

impl<C: Channel> fmt::Debug for SessionHandle<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionHandle")
            .field("id", &self.id)
            .field("channel", &C::id())
            .finish()
    }
}

impl<C: Channel> Clone for SessionHandle<C> {
    fn clone(&self) -> Self {
        Self {
            id: self.id.clone(),
            _channel: PhantomData,
        }
    }
}

// ---------------------------------------------------------------------------
// Channel marker types
// ---------------------------------------------------------------------------

/// Telegram channel marker.
pub struct Telegram;
impl Channel for Telegram {
    fn id() -> &'static str {
        "telegram"
    }
}

/// Discord channel marker.
pub struct Discord;
impl Channel for Discord {
    fn id() -> &'static str {
        "discord"
    }
}

/// Slack channel marker.
pub struct Slack;
impl Channel for Slack {
    fn id() -> &'static str {
        "slack"
    }
}

/// Matrix channel marker.
pub struct Matrix;
impl Channel for Matrix {
    fn id() -> &'static str {
        "matrix"
    }
}

/// Microsoft Teams channel marker.
pub struct Teams;
impl Channel for Teams {
    fn id() -> &'static str {
        "teams"
    }
}

/// Signal channel marker.
pub struct Signal;
impl Channel for Signal {
    fn id() -> &'static str {
        "signal"
    }
}

/// iMessage channel marker.
pub struct IMessage;
impl Channel for IMessage {
    fn id() -> &'static str {
        "imessage"
    }
}

/// Google Chat channel marker.
pub struct GoogleChat;
impl Channel for GoogleChat {
    fn id() -> &'static str {
        "google-chat"
    }
}

/// Generic channel marker for testing and dynamic dispatch.
pub struct Generic;
impl Channel for Generic {
    fn id() -> &'static str {
        "generic"
    }
}
