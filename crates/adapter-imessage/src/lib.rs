pub mod adapter;
pub mod commands;
pub mod convert;
pub mod error;

pub use adapter::IMessageAdapter;
pub use error::IMessageError;

#[cfg(test)]
mod tests;
