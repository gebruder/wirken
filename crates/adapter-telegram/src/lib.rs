pub mod adapter;
pub mod convert;
pub mod error;

pub use adapter::TelegramAdapter;
pub use error::TelegramError;

#[cfg(test)]
mod tests;
