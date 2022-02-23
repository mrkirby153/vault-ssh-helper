extern crate core;

use anyhow::{Result};
use vaultrs::client::{VaultClient};

use crate::config::{Config, merge};
pub use crate::errors::Error;

pub mod config;
mod errors;
pub mod vault;
pub mod console;
pub mod ssh;


/// Loads the configuration from the given path
pub fn load_config(path: &str) -> Result<Config> {
    merge(Config::new(path)?, Config::parse_from_cli())
}