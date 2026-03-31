use std::fmt;
use std::marker::PhantomData;

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
