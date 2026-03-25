pub mod adapter;
pub mod convert;
pub mod error;

pub use adapter::SlackAdapter;
pub use error::SlackError;

#[cfg(test)]
mod tests;
