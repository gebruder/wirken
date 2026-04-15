pub mod adapter;
pub mod convert;
pub mod error;

pub use adapter::SignalAdapter;
pub use convert::SignalAllowlist;
pub use error::SignalError;

#[cfg(test)]
mod tests;
