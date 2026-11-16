//! What went wrong, as an exit code a script can act on.

use std::fmt;

/// Why a command didn't do what it was asked, with the exit code that says so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub code: u8,
    pub message: String,
}

impl Failure {
    /// `--exit-code` found something.
    pub const FOUND: u8 = 1;
    /// The command itself was wrong.
    pub const USAGE: u8 = 2;
    /// Nothing by that name, or more than one.
    pub const NOT_FOUND: u8 = 3;
    /// Not signed in, or the role doesn't allow it.
    pub const NOT_ALLOWED: u8 = 4;
    /// The server looked at it and said no, with its reason.
    pub const REFUSED: u8 = 5;
    /// The server couldn't be reached, or waiting ran out.
    pub const UNREACHABLE: u8 = 6;

    pub fn new(code: u8, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn usage(message: impl Into<String>) -> Self {
        Self::new(Self::USAGE, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(Self::NOT_FOUND, message)
    }

    pub fn not_allowed(message: impl Into<String>) -> Self {
        Self::new(Self::NOT_ALLOWED, message)
    }

    pub fn refused(message: impl Into<String>) -> Self {
        Self::new(Self::REFUSED, message)
    }

    pub fn unreachable(message: impl Into<String>) -> Self {
        Self::new(Self::UNREACHABLE, message)
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for Failure {}

/// The exit code for an error: its own, or 1 for anything else.
pub fn exit_code(error: &anyhow::Error) -> u8 {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<Failure>())
        .map_or(1, |failure| failure.code)
}
