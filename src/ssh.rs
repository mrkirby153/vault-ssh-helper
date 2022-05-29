use std::{fs, path};
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, Result};
use rand::{distributions::Alphanumeric, Rng};
use sshkeys::Certificate;
use thiserror::Error;
use tokio::io;
use tokio_stream::StreamExt;
use tokio_util::codec::{BytesCodec, FramedRead, FramedWrite};
use tracing::debug;
use vaultrs::api::ssh::requests::SignSSHKeyRequest;
use vaultrs::client::VaultClient;
use vaultrs::error::ClientError;
use vaultrs::ssh;

use crate::Config;
use crate::console::Console;
use crate::ssh::Error::{KeystoreDirNotFound, VaultApiError};
use crate::vault::get_vault_client;

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
    debug!("Checking validity of certificate {}", path);
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

    debug!(
        "Contains principal {}? {}",
        user,
        cert.valid_principals.contains(&user.to_string())
    );
    debug!("Expired? {}", is_expired);

    if !cert.valid_principals.contains(&user.to_string()) || is_expired {
        Ok(false)
    } else {
        Ok(true)
    }
}

pub async fn get_or_sign_key(host: &str, logger: &dyn Console, cfg: &Config) -> Result<String> {
    let pubkey = fs::read_to_string(private_to_public(cfg.identity.as_ref().unwrap()))?;
    let keyfile_path = get_key_from_keystore(host, cfg)?;
    get_or_sign_key_raw(host, &pubkey, keyfile_path, logger, cfg).await
}

/// Gets the signed key if it is valid, otherwise sign it
pub async fn get_or_sign_key_raw(host: &str, pubkey: &str, certificate_path: String, logger: &dyn Console, cfg: &Config) -> Result<String> {
    let user = get_ssh_user(host)?;

    logger.info(&format!("Connecting to {} as {}...", host, user));

    let needs_sign = if let Err(_) = check_ssh_file(&certificate_path) {
        logger.info(&format!(
            "Certificate does not exist. Retrieving a new one..."
        ));
        true
    } else if !is_certificate_valid(&certificate_path, &user)? {
        logger.info(&format!("Certificate is no longer valid, refreshing..."));
        true
    } else {
        false
    };

    if needs_sign {
        debug!("Initializing vault client");
        let vault = get_vault_client(cfg).await?;
        let signed_pubkey = sign_key(&user, cfg, &vault, &pubkey).await?;
        debug!("Writing signed key to {}", &certificate_path);
        fs::write(&certificate_path, signed_pubkey.as_bytes())?;
        // Ensure proper permissions for ssh keyfile
        fs::set_permissions(
            &certificate_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )?;

        logger.info(&format!("Wrote certificate to {}", certificate_path));
    }
    Ok(certificate_path)
}

async fn sign_key(user: &str, cfg: &Config, vault: &VaultClient, pubkey: &str) -> Result<String> {
    debug!("Signing key {} with principal {}", pubkey, user);
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
    debug!("Retrieving key for {} from keystore", host);
    let dir = path::Path::new(dir);

    if !dir.exists() {
        fs::create_dir_all(dir)?;
    }

    let path = dir.join(sha256::digest(host));
    debug!("Reading key: {:?}", &path);
    Ok(String::from(path.as_path().to_str().unwrap()))
}

fn get_ssh_option(ssh_host: &str, key: &str) -> Result<String> {
    debug!("Retrieving param {} for host {}", key, ssh_host);
    let cmd = Command::new("ssh").arg("-G").arg(ssh_host).output()?;
    if !cmd.status.success() {
        return Err(anyhow!(SshError::UserNotFound));
    }

    let stdout = String::from_utf8(cmd.stdout)?;

    for line in stdout.split("\n") {
        if line.starts_with(key) {
            let line: Vec<&str> = line.split(" ").collect();
            if line.len() != 2 {
                return Err(anyhow!(SshError::InvalidSshFormattedMessage {
                    host: String::from(ssh_host)
                }));
            }
            let opt = line[1].to_string();
            return Ok(opt);
        }
    }
    Err(anyhow!("Parameter {} not found in ssh -G", key))
}

/// Gets the actual user that the ssh client will use to connect
fn get_ssh_user(host: &str) -> Result<String> {
    debug!("Retrieving ssh user for host {}", host);
    get_ssh_option(host, "user")
}

fn private_to_public(path: &str) -> PathBuf {
    let mut pathbuf = PathBuf::from(path);
    pathbuf.set_extension("pub");
    pathbuf
}

fn private_to_cert(path: &str) -> PathBuf {
    let mut path = String::from(path);
    path.push_str("-cert");
    let mut pathbuf = PathBuf::from(path);
    pathbuf.set_extension("pub");
    pathbuf
}

pub fn clean_stale_keys(keystore_dir: &str, console: &dyn Console) -> u64 {
    let remove_key = |buff: &PathBuf| {
        debug!("Removing key {:?}", buff);
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

pub async fn generate_temp_ssh_key_and_add_to_agent(store_dir: &str, host: &str, logger: &dyn Console, cfg: &Config, sign: Option<bool>) -> Result<String> {
    let should_sign = sign.unwrap_or(false);

    let keyfile: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(7)
        .map(char::from)
        .collect();

    let keyfile = Path::new(store_dir).join(keyfile);
    let path = match keyfile.to_str() {
        Some(x) => Ok(x),
        None => Err(anyhow!("Failed to generate path"))
    }?;

    let result = Command::new("ssh-keygen").args(["-f", &path, "-N", ""]).output()?;
    debug!("ssh-keygen stdout: {}", String::from_utf8_lossy(&result.stdout));
    debug!("ssh-keygen stderr: {}", String::from_utf8_lossy(&result.stderr));
    if !result.status.success() {
        return Err(anyhow!("Failed to generate key"));
    }

    if should_sign {
        debug!("Signing newly generated key");
        let pubkey = fs::read_to_string(private_to_public(path))?;
        let _ = get_or_sign_key_raw(host, &pubkey, String::from(private_to_cert(path).to_str().unwrap()), logger, cfg).await;
    }

    let result = Command::new("ssh-add").arg(&path).output()?;
    debug!("ssh-add stdout: {}", String::from_utf8_lossy(&result.stdout));
    debug!("ssh-add stderr: {}", String::from_utf8_lossy(&result.stderr));
    if !result.status.success() {
        return Err(anyhow!("Failed to add key to agent"));
    }
    Ok(String::from(path))
}


pub fn remove_key_from_agent(path: &String) -> Result<()> {
    let result = Command::new("ssh-add").args(["-d", &path]).output()?;
    debug!("ssh-add stdout: {}", String::from_utf8_lossy(&result.stdout));
    debug!("ssh-add stderr: {}", String::from_utf8_lossy(&result.stderr));
    if !result.status.success() {
        return Err(anyhow!("Failed to remove key from agent"));
    }
    // Clean up keyfiles
    let to_delete = [PathBuf::from(path), private_to_public(path), private_to_cert(path)];

    for f in to_delete {
        if let Err(x) = fs::remove_file(&f) {
            println!("Could not remove file: {:?}, {:?}", f, x);
        }
    }
    Ok(())
}

pub async fn raw_tunnel(host: &str, keypath: String) -> Result<()> {
    let ssh_hostname = get_ssh_option(host, "hostname")?;
    let ssh_port = get_ssh_option(host, "port")?;
    let mut address = String::from(ssh_hostname);
    address.push_str(":");
    address.push_str(&ssh_port);


    let stdin = FramedRead::new(io::stdin(), BytesCodec::new());
    let stdin = stdin.map(|i| i.map(|bytes| bytes.freeze()));
    let stdout = FramedWrite::new(io::stdout(), BytesCodec::new());
    let server: Vec<_> = address
        .to_socket_addrs()?
        .collect();
    let addr = server.first().unwrap();

    tcp_forward::connect(&addr, stdin, stdout).await.map_err(|e| { anyhow!("TCP forward error={}", e) })?;

    Ok(())
}

mod tcp_forward {
    use std::{error::Error, io, net::SocketAddr};

    use bytes::Bytes;
    use futures::{future, Sink, SinkExt, Stream, StreamExt};
    use tokio::net::TcpStream;
    use tokio_util::codec::{BytesCodec, FramedRead, FramedWrite};

    pub async fn connect(
        addr: &SocketAddr,
        mut stdin: impl Stream<Item=Result<Bytes, io::Error>> + Unpin,
        mut stdout: impl Sink<Bytes, Error=io::Error> + Unpin,
    ) -> Result<(), Box<dyn Error>> {
        let mut stream = TcpStream::connect(addr).await?;
        let (r, w) = stream.split();
        let mut sink = FramedWrite::new(w, BytesCodec::new());
        // filter map Result<BytesMut, Error> stream into just a Bytes stream to match stdout Sink
        // on the event of an Error, log the error and end the stream
        let mut stream = FramedRead::new(r, BytesCodec::new())
            .filter_map(|i| match i {
                //BytesMut into Bytes
                Ok(i) => future::ready(Some(i.freeze())),
                Err(e) => {
                    println!("failed to read from socket; error={}", e);
                    future::ready(None)
                }
            })
            .map(Ok);

        match future::join(sink.send_all(&mut stdin), stdout.send_all(&mut stream)).await {
            (Err(e), _) | (_, Err(e)) => Err(e.into()),
            _ => Ok(()),
        }
    }
}