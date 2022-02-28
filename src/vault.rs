use std::{fs, path};

use anyhow::{anyhow, Result};
use thiserror::Error;
use vaultrs::client::{Client, VaultClient, VaultClientSettingsBuilder};
use vaultrs::sys::ServerStatus as VaultServerStatus;

use crate::Config;

#[derive(Error, Debug)]
pub enum Error {
    #[error("No token was found. Run \"vault login\" to generate and save one")]
    TokenNotFound,
    #[error("The vault is sealed")]
    VaultSealed,
    #[error("The vault token is not valid")]
    TokenInvalid,
    #[error("The vault is not initialized")]
    Uninitialized,
    #[error("The vault was in an invalid state: {0:?}")]
    InvalidState(VaultServerStatus),
    #[error("An error occurred: {0}")]
    ClientError(vaultrs::error::ClientError),
    #[error("An unknown vault error occurred")]
    Generic,
}

fn read_vault_token(token_file: &str) -> Result<String> {
    let path = path::Path::new(token_file);
    if !path.exists() {
        return Err(anyhow! { Error::TokenNotFound });
    }

    let token = fs::read_to_string(token_file).map_err(|e| anyhow!(e))?;
    Ok(token)
}

pub fn build_client(addr: &str, token_file: &str) -> Result<VaultClient> {
    let client = VaultClient::new(
        VaultClientSettingsBuilder::default()
            .address(addr)
            .token(read_vault_token(token_file)?)
            .build()
            .unwrap(),
    )
    .map_err(|e| anyhow!(e));

    client
}

pub async fn get_vault_client(config: &Config) -> Result<VaultClient> {
    let client = build_client(
        config.vault_address.as_ref().unwrap(),
        config.token_path.as_ref().unwrap(),
    )
    .map_err(|e| anyhow!(e))?;

    let status = client
        .status()
        .await
        .map_err(|e| anyhow!(Error::ClientError(e)))?;

    match status {
        VaultServerStatus::OK => client
            .lookup()
            .await
            .map_err(|e| anyhow!(try_parse_api_error(e))),
        VaultServerStatus::SEALED => Err(anyhow!(Error::VaultSealed)),
        VaultServerStatus::UNINITIALIZED => Err(anyhow!(Error::Uninitialized)),
        s => Err(anyhow!(Error::InvalidState(s))),
    }?;

    Ok(client)
}

fn try_parse_api_error(e: vaultrs::error::ClientError) -> Error {
    match e {
        vaultrs::error::ClientError::APIError {
            code,
            errors: ref _errors,
        } => {
            if code == 401 || code == 403 {
                Error::TokenInvalid
            } else {
                Error::ClientError(e)
            }
        }
        _ => Error::ClientError(e),
    }
}
