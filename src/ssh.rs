use std::path::PathBuf;
use std::process::Command;
use std::{fs, path};

use anyhow::{anyhow, Result};
use sshkeys::Certificate;
use thiserror::Error;
use vaultrs::api::ssh::requests::SignSSHKeyRequest;
use vaultrs::client::VaultClient;
use vaultrs::error::ClientError;
use vaultrs::ssh;

use crate::console::Console;
use crate::ssh::Error::{KeystoreDirNotFound, VaultApiError};
use crate::Config;

#[derive(Debug, Error)]
pub enum Error {
    #[error("SSH key not found")]
    KeyNotFound,
    #[error("Keystore directory not found")]
    KeystoreDirNotFound,
    #[error("Vault API Error ({code}): {errors:?}")]
    VaultApiError { code: u16, errors: Vec<String> },
}

#[derive(Debug, Error)]
pub enum SshError {
    #[error("Could not determine the ssh user")]
    UserNotFound,
    #[error("ssh -G {host} did not produce the expected format")]
    InvalidSshFormattedMessage { host: String },
}

/// Checks if the provided ssh file exists
pub fn check_ssh_file(path: &str) -> Result<()> {
    let path = path::Path::new(path);
    if !path.exists() {
        return Err(anyhow!(Error::KeyNotFound));
    }
    Ok(())
}

pub fn is_certificate_valid(path: &str, user: &str) -> Result<bool> {
    let cert = match Certificate::from_path(path) {
        Ok(x) => x,
        Err(_) => {
            return Ok(false);
        }
    };

    let curr_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let is_expired = curr_time > cert.valid_before;

    if !cert.valid_principals.contains(&user.to_string()) || is_expired {
        Ok(false)
    } else {
        Ok(true)
    }
}

/// Gets the signed key if it is valid, otherwise sign it
pub async fn get_or_sign_key(
    host: &str,
    logger: &dyn Console,
    cfg: &Config,
    vault: &VaultClient,
) -> Result<String> {
    let keyfile_path = get_key_from_keystore(host, cfg)?;
    let pubkey = fs::read_to_string(private_to_public(cfg.identity.as_ref().unwrap()))?;

    let user = get_ssh_user(host)?;

    logger.info(&format!("Connecting to {} as {}...", host, user));

    let needs_sign = if let Err(_) = check_ssh_file(&keyfile_path) {
        logger.info(&format!(
            "Certificate does not exist. Retrieving a new one..."
        ));
        true
    } else if !is_certificate_valid(&keyfile_path, &user)? {
        logger.info(&format!("Certificate is no longer valid, refreshing..."));
        true
    } else {
        false
    };

    if needs_sign {
        let signed_pubkey = sign_key(&user, cfg, vault, &pubkey).await?;

        fs::write(&keyfile_path, signed_pubkey.as_bytes())?;
        // Ensure proper permissions for ssh keyfile
        fs::set_permissions(
            &keyfile_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )?;

        logger.info(&format!("Wrote certificate to {}", keyfile_path));
    }
    Ok(keyfile_path)
}

async fn sign_key(user: &str, cfg: &Config, vault: &VaultClient, pubkey: &str) -> Result<String> {
    let mut builder = SignSSHKeyRequest::builder();
    builder.valid_principals(user);

    let cert = ssh::ca::sign(
        vault,
        cfg.auth_mount.as_ref().unwrap(),
        cfg.role.as_ref().unwrap(),
        pubkey,
        Some(&mut builder),
    )
    .await;

    match cert {
        Ok(x) => Ok(x.signed_key),
        Err(err) => match err {
            ClientError::APIError { code, errors } => Err(anyhow!(VaultApiError { code, errors })),
            x => Err(anyhow!(x)),
        },
    }
}

/// Gets the path of the key from the keystore
fn get_key_from_keystore(host: &str, cfg: &Config) -> Result<String> {
    let dir = match cfg.key_path.as_ref() {
        None => {
            return Err(anyhow!(KeystoreDirNotFound));
        }
        Some(s) => s,
    };
    let dir = path::Path::new(dir);

    if !dir.exists() {
        fs::create_dir_all(dir)?;
    }

    let path = dir.join(sha256::digest(host));
    Ok(String::from(path.as_path().to_str().unwrap()))
}

/// Gets the actual user that the ssh client will use to connect
fn get_ssh_user(host: &str) -> Result<String> {
    let cmd = Command::new("ssh").arg("-G").arg(host).output()?;
    if !cmd.status.success() {
        return Err(anyhow!(SshError::UserNotFound));
    }

    let stdout = String::from_utf8(cmd.stdout)?;

    for line in stdout.split("\n") {
        if line.starts_with("user") {
            let line: Vec<&str> = line.split(" ").collect();
            if line.len() != 2 {
                return Err(anyhow!(SshError::InvalidSshFormattedMessage {
                    host: String::from(host)
                }));
            }
            return Ok(line[1].to_string());
        }
    }
    Err(anyhow!(SshError::UserNotFound))
}

fn private_to_public(path: &str) -> PathBuf {
    let mut pathbuf = PathBuf::from(path);
    pathbuf.set_extension("pub");
    pathbuf
}

pub fn clean_stale_keys(keystore_dir: &str, console: &dyn Console) -> u64 {
    let remove_key = |buff: &PathBuf| {
        if let Err(e) = fs::remove_file(buff) {
            console.err(&format!(
                "Could not remove stale key {} because {}",
                buff.to_string_lossy(),
                e
            ))
        }
    };

    let mut deleted = 0;

    let files = fs::read_dir(keystore_dir);
    if let Err(e) = files {
        console.warn(&format!("Could not clean stale keys: {}", e));
        return 0;
    }

    let curr_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for file in files.unwrap() {
        let file = file.unwrap().path();
        let cert = Certificate::from_path(&file);
        match cert {
            Ok(cert) => {
                if curr_time > cert.valid_before {
                    deleted += 1;
                    remove_key(&file);
                }
            }
            Err(_) => {
                console.warn(&format!(
                    "{} is not a valid certificate, removing...",
                    file.to_string_lossy()
                ));
                remove_key(&file);
            }
        };
    }
    deleted
}
