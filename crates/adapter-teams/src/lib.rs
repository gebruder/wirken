pub mod adapter;
pub mod convert;
pub mod error;

pub use adapter::TeamsAdapter;
pub use error::TeamsError;

#[cfg(test)]
mod tests;
