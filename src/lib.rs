extern crate core;

use anyhow::Result;
use clap::Parser;

use crate::config::{merge, Config};

pub mod config;
pub mod console;
pub mod ssh;
pub mod vault;

#[derive(Parser, Debug)]
#[clap(version, about)]
pub struct Opts {
    /// The auth method to use
    #[clap(short = 'a', long)]
    pub auth: Option<String>,
    /// The auth mount
    #[clap(short = 'm', long)]
    pub auth_mount: Option<String>,
    /// Disable terminal effects
    #[clap(short = 'b', long)]
    pub basic: bool,
    /// Enable debug logging
    #[clap(short='d', long)]
    pub debug: bool,
    /// The identity file to use. Defaults to ~/.ssh/id_rsa
    #[clap(short, long)]
    pub identity: Option<String>,
    /// Persist the vault token
    #[clap(short, long)]
    pub persist: Option<bool>,
    /// The role to use when authenticating
    #[clap(short, long)]
    pub role: Option<String>,
    /// Where on disk to store the keys. Defaults to ~/.local/share/vault_ssh_helper/keys
    #[clap(short, long)]
    pub key_path: Option<String>,
    /// Where on disk the token is stored. Defaults to ~/.vault_token
    #[clap(short, long)]
    pub token_path: Option<String>,
    /// The vault server to communicate with
    #[clap(short, long)]
    pub vault_address: Option<String>,

    /// The SSH host to connect to
    pub host: String,
    /// Any additional ssh arguments
    pub args: Vec<String>,
}

/// Loads the configuration from the given path
pub fn load_config(path: &str, opts: Opts) -> Result<Config> {
    merge(Config::new(path)?, opts)
}
