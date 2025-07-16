use crossterm::style::Stylize;
use std::fmt;

#[derive(Debug)]
pub enum VlitzError {
    DeviceNotFound,
    ProcessNotFound(String),
    ProcessKillFailed(String),
    AttachFailed(String),
    ScriptCreationFailed(String),
    ScriptLoadFailed(String),
    SessionDetached,
    SpawnFailed(String),
    ResumeFailed(String),
    MessageHandlerFailed(String),
}

impl fmt::Display for VlitzError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VlitzError::DeviceNotFound => write!(f, "{}", "No device found".red()),
            VlitzError::ProcessNotFound(target) => write!(
                f,
                "{} {}",
                "Process not found:".red(),
                target.clone().yellow()
            ),
            VlitzError::ProcessKillFailed(reason) => {
                write!(f, "{} {}", "Failed to kill process:".red(), reason)
            }
            VlitzError::AttachFailed(reason) => {
                write!(f, "{} {}", "Failed to attach process:".red(), reason)
            }
            VlitzError::ScriptCreationFailed(reason) => {
                write!(f, "{} {}", "Failed to create script:".red(), reason)
            }
            VlitzError::ScriptLoadFailed(reason) => {
                write!(f, "{} {}", "Failed to load script:".red(), reason)
            }
            VlitzError::SessionDetached => write!(f, "{}", "Session detached...".yellow().bold()),
            VlitzError::SpawnFailed(reason) => {
                write!(f, "{} {}", "Failed to spawn process:".red(), reason)
            }
            VlitzError::ResumeFailed(reason) => {
                write!(f, "{} {}", "Failed to resume process:".red(), reason)
            }
            VlitzError::MessageHandlerFailed(reason) => {
                write!(f, "{} {}", "Failed to set message handler:".red(), reason)
            }
        }
    }
}

impl std::error::Error for VlitzError {}

pub type VlitzResult<T> = Result<T, VlitzError>;
