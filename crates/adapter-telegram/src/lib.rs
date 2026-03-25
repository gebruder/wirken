pub mod adapter;
pub mod error;
pub mod convert;

pub use adapter::TelegramAdapter;
pub use error::TelegramError;

#[cfg(test)]
mod tests;
