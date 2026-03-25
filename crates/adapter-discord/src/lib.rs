pub mod adapter;
pub mod convert;
pub mod error;

pub use adapter::DiscordAdapter;
pub use error::DiscordError;

#[cfg(test)]
mod tests;
