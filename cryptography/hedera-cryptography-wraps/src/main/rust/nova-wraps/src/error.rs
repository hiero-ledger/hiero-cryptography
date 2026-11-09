//! Errors returned by WRAPS operations.

/// Why a WRAPS operation was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WrapsError {
  /// The caller supplied something inconsistent, malformed, or unauthorised.
  InvalidInput(String),
  /// One or more participants supplied invalid signing-round messages.
  ///
  /// One flag per selected signer, in round-message order. The flags identify offenders
  /// detected by this call: `false` marks a detected offender; `true` means not flagged.
  /// Validation stops at the first failing stage. An offender whose invalid message
  /// would be caught by a later stage can therefore still have a `true` flag.
  /// Therefore, this array only identifies a subset of offenders.
  InvalidMessages { valid_messages: Vec<bool> },
  /// A cryptographic primitive or the proof system itself failed.
  Cryptography(String),
}

impl WrapsError {
  pub(crate) fn invalid_input(msg: impl Into<String>) -> Self {
    Self::InvalidInput(msg.into())
  }

  pub(crate) fn invalid_messages(valid_messages: Vec<bool>) -> Self {
    Self::InvalidMessages { valid_messages }
  }

  pub(crate) fn cryptography(msg: impl Into<String>) -> Self {
    Self::Cryptography(msg.into())
  }
}

impl std::fmt::Display for WrapsError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::InvalidInput(msg) => write!(f, "invalid input: {msg}"),
      Self::InvalidMessages { .. } => write!(f, "invalid signing-round messages"),
      Self::Cryptography(msg) => write!(f, "cryptography error: {msg}"),
    }
  }
}

impl std::error::Error for WrapsError {}
