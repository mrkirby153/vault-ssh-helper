use std::{fs, path};

use anyhow::{anyhow, Result};
use clap::Parser;
use serde::Deserialize;

use crate::Error;
use crate::Error::MissingArgumentError;

#[derive(Deserialize, Debug, Default, Parser)]
#[clap(version, about)]
pub struct Config {
    /// The auth method to use
    #[clap(short = 'a', long)]
    auth: Option<String>,
    /// The auth mount
    #[clap(short = 'm', long)]
    auth_mount: Option<String>,
    /// The identity file to use. Defaults to ~/.ssh/id_rsa
    #[clap(short, long)]
    identity: Option<String>,
    /// Persist the vault token
    #[clap(short, long)]
    persist: Option<bool>,
    /// The role to use when authenticating
    #[clap(short, long)]
    role: Option<String>,
    /// Where on disk to store the keys. Defaults to ~/.local/share/vault_ssh_helper/keys
    #[clap(short, long)]
    key_path: Option<String>,

    /// Where on disk the token is stored. Defaults to ~/.vault_token
    #[clap(short, long)]
    token_path: Option<String>
}

impl Config {
    pub fn parse_from_cli() -> Config {
        Config::parse()
    }

    fn new_empty() -> Config {
        Config {
            auth: None,
            auth_mount: None,
            identity: None,
            persist: None,
            role: None,
            key_path: None,
            token_path: None,
        }
    }

    pub fn new(path: &str) -> Result<Config> {
        let fs_path = path::Path::new(path);
        if !fs_path.exists() {
            return Ok(Config::new_empty());
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

/// Merge the provided config and cli config. The CLI config takes precedence over the provided config
pub fn merge(config: Config, cli_config: Config) -> Result<Config> {
    Ok(Config {
        auth: do_merge("auth", config.auth, cli_config.auth, None, true)?,
        auth_mount: do_merge("auth_mount", config.auth_mount, cli_config.auth_mount, Some(String::from("ssh")), true)?,
        identity: expand_shell(do_merge("identity", config.identity, cli_config.identity, Some(String::from("~/.ssh/id_rsa")), true)?),
        persist: do_merge("persist", config.persist, cli_config.persist, Some(true), true)?,
        role: do_merge("role", config.role, cli_config.role, None, true)?,
        key_path: expand_shell(do_merge("key_path", config.key_path, cli_config.key_path, Some(String::from("~/.local/share/vault_ssh_helper/keys")), true)?),
        token_path: expand_shell(do_merge("token_path", config.token_path, cli_config.token_path, Some(String::from("~/.vault-token")), true)?)
    })
}

fn expand_shell(str: Option<String>) -> Option<String> {
    if let Some(t) = str {
        Some(shellexpand::tilde(&t).to_string())
    } else {
        None
    }
}

fn do_merge<T>(name: &str, config: Option<T>, cli_config: Option<T>, default: Option<T>, required: bool) -> Result<Option<T>> {
    match cli_config {
        Some(t) => Ok(Some(t)),
        None => match config {
            Some(t) => Ok(Some(t)),
            None => match default {
                Some(t) => Ok(Some(t)),
                None => {
                    if required {
                        Err(anyhow!(MissingArgumentError {name: String::from(name)}))
                    } else {
                        Ok(None)
                    }
                }
            }
        }
    }
}