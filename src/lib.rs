extern crate core;

use anyhow::Result;

use crate::config::{Config, merge};
use crate::errors::Error;

mod config;
mod errors;


/// Loads the configuration from the given path
pub fn load_config(path: &str) -> Result<Config> {
    merge(Config::new(path)?, Config::parse_from_cli())
}