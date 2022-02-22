extern crate core;

use anyhow::{Result};
use vaultrs::client::{VaultClient};

use crate::config::{Config, merge};
use crate::errors::Error;

mod config;
mod errors;
mod vault;


/// Loads the configuration from the given path
pub fn load_config(path: &str) -> Result<Config> {
    merge(Config::new(path)?, Config::parse_from_cli())
}

pub async fn get_vault_client(config: &Config) -> Result<VaultClient> {
    vault::get_vault_client(config).await
}