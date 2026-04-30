#[cfg(unix)]
pub mod adapter;
pub mod convert;
pub mod error;

#[cfg(unix)]
pub use adapter::SignalAdapter;
pub use convert::{SignalAllowlist, SignalAllowlistError};
pub use error::SignalError;

#[cfg(test)]
mod tests;
