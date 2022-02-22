extern crate core;

use anyhow::Result;

use crate::config::Config;
use crate::errors::Error;

mod config;
mod errors;


/// Loads the configuration from the given path
pub fn load_config(path: &str) -> Result<Config> {
    Config::new(path)
}