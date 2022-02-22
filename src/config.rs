use std::{fs, path};

use anyhow::{anyhow, Result};
use serde::Deserialize;

use crate::Error;
use crate::Error::ConfigNotFoundError;

#[derive(Deserialize, Debug, Default)]
pub struct Config {
    /// The auth method to use
    auth: Option<String>,
    /// The auth mount
    auth_mount: Option<String>,
    /// The identity file to use
    identity: Option<String>,
    /// Persist the vault token
    persist: Option<bool>,
    /// The role to use when authenticating
    role: Option<String>,
}


impl Config {
    pub fn new(path: &str) -> Result<Config> {
        let fs_path = path::Path::new(path);
        if !fs_path.exists() {
            return Err(
                anyhow! { ConfigNotFoundError {path: String::from(path)}}
            );
        }
        let contents = fs::read_to_string(path).map_err(|e| {
            anyhow! { Error::IOError {source: e}}
        })?;
        toml::from_str(&contents).map_err(|e| {
            anyhow! {
                Error::ConfigParseError {source: e}
            }
        })
    }
}