pub mod adapter;
pub mod convert;
pub mod error;

pub use adapter::MatrixAdapter;
pub use error::MatrixError;

#[cfg(test)]
mod tests;
