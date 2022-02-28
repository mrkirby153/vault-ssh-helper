use std::{fs, path};

use anyhow::{anyhow, Result};
use serde::Deserialize;
use thiserror::Error;
use tracing::debug;

use crate::Opts;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Configuration parse failed: {source}")]
    ConfigParseError { source: toml::de::Error },
    #[error("An I/O error occurred: {source}")]
    IOError {
        #[from]
        source: std::io::Error,
    },
    #[error("Missing parameter: {name}")]
    MissingArgumentError { name: String },
}

#[derive(Deserialize, Debug)]
pub struct Config {
    pub auth: Option<String>,
    pub auth_mount: Option<String>,
    pub identity: Option<String>,
    pub persist: Option<bool>,
    pub role: Option<String>,
    pub key_path: Option<String>,
    pub token_path: Option<String>,
    pub vault_address: Option<String>,
}

impl Config {
    fn new_empty() -> Config {
        Config {
            auth: None,
            auth_mount: None,
            identity: None,
            persist: None,
            role: None,
            key_path: None,
            token_path: None,
            vault_address: None,
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
pub fn merge(config: Config, cli_config: Opts) -> Result<Config> {
    // Check if the vault address is set
    let vault_addr_env = std::env::var("VAULT_ADDR");
    let config_vault_addr = do_merge(
        "vault_address",
        config.vault_address,
        cli_config.vault_address,
        None,
        false,
    )?;

    let vault_address = if let Some(x) = config_vault_addr {
        debug!("Using vault address {} from configuration", x);
        x
    } else {
        if let Ok(var) = vault_addr_env {
            debug!("Using vault address {} from VAULT_ADDR", var);
            var
        } else {
            String::from("http://localhost:8200")
        }
    };
    Ok(Config {
        auth: do_merge("auth", config.auth, cli_config.auth, None, true)?,
        auth_mount: do_merge(
            "auth_mount",
            config.auth_mount,
            cli_config.auth_mount,
            Some(String::from("ssh")),
            true,
        )?,
        identity: expand_shell(do_merge(
            "identity",
            config.identity,
            cli_config.identity,
            Some(String::from("~/.ssh/id_rsa")),
            true,
        )?),
        persist: do_merge(
            "persist",
            config.persist,
            cli_config.persist,
            Some(true),
            true,
        )?,
        role: do_merge("role", config.role, cli_config.role, None, true)?,
        key_path: expand_shell(do_merge(
            "key_path",
            config.key_path,
            cli_config.key_path,
            Some(String::from("~/.local/share/vault_ssh_helper/keys")),
            true,
        )?),
        token_path: expand_shell(do_merge(
            "token_path",
            config.token_path,
            cli_config.token_path,
            Some(String::from("~/.vault-token")),
            true,
        )?),
        vault_address: Some(vault_address),
    })
}

fn expand_shell(str: Option<String>) -> Option<String> {
    if let Some(t) = str {
        Some(shellexpand::tilde(&t).to_string())
    } else {
        None
    }
}

fn do_merge<T>(
    name: &str,
    config: Option<T>,
    cli_config: Option<T>,
    default: Option<T>,
    required: bool,
) -> Result<Option<T>> {
    match cli_config {
        Some(t) => Ok(Some(t)),
        None => match config {
            Some(t) => Ok(Some(t)),
            None => match default {
                Some(t) => Ok(Some(t)),
                None => {
                    if required {
                        Err(anyhow!(Error::MissingArgumentError {
                            name: String::from(name)
                        }))
                    } else {
                        Ok(None)
                    }
                }
            },
        },
    }
}
