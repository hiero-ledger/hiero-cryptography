//! Errors returned by WRAPS operations.

/// Why a WRAPS operation was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WrapsError {
  /// The caller supplied something inconsistent, malformed, or unauthorised.
  InvalidInput(String),
  /// A cryptographic primitive or the proof system itself failed.
  Cryptography(String),
}

impl WrapsError {
  pub(crate) fn invalid_input(msg: impl Into<String>) -> Self {
    Self::InvalidInput(msg.into())
  }

  pub(crate) fn cryptography(msg: impl Into<String>) -> Self {
    Self::Cryptography(msg.into())
  }
}

impl std::fmt::Display for WrapsError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::InvalidInput(msg) => write!(f, "invalid input: {msg}"),
      Self::Cryptography(msg) => write!(f, "cryptography error: {msg}"),
    }
  }
}

impl std::error::Error for WrapsError {}
