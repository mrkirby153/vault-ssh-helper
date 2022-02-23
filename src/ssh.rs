use std::path;

use anyhow::{anyhow, Result};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("SSH key not found")]
    KeyNotFound
}

/// Checks if the provided ssh file exists
pub fn check_ssh_file(path: &str) -> Result<()> {
    let path = path::Path::new(path);
    if !path.exists() {
        return Err(anyhow!(Error::KeyNotFound));
    }
    Ok(())
}