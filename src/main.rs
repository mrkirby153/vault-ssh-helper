use std::error::Error;
use std::path::Path;
use std::process::{exit, Command};

use anyhow::{anyhow, Result};
use clap::Parser;

use vault_ssh_helper::console::{ColorConsole, Console, PlainConsole};
use vault_ssh_helper::{load_config, Opts};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let opts: Opts = Opts::parse();

    let console: Box<dyn Console> = if opts.basic {
        Box::new(PlainConsole)
    } else {
        Box::new(ColorConsole::new())
    };
    let console = console.as_ref();

    // Clone these so we can use them later
    let host = opts.host.clone();
    let args = opts.args.clone();

    // Load the config
    let config = load_config(&get_config_path()?, opts)?;

    let stale_keys_removed =
        vault_ssh_helper::ssh::clean_stale_keys(config.key_path.as_ref().unwrap(), console);
    if stale_keys_removed > 0 {
        console.info(&format!("Cleaned up {} stale keys...", stale_keys_removed))
    }

    // Check if the ssh keyfile exists
    let ssh_path = config.identity.as_ref().unwrap_or_else(|| {
        console.err("Identity file not specified");
        exit(1);
    });

    console.info(&format!(
        "Attempting to connect to {} with ssh key {}...",
        host, ssh_path
    ));

    if let Err(e) = vault_ssh_helper::ssh::check_ssh_file(&ssh_path[..]) {
        console.err(&format!("Error: {}", e)[..]);
        exit(1);
    }
    let certificate_path =
        vault_ssh_helper::ssh::get_or_sign_key(&host, console, &config).await.unwrap_or_else(|e| {
            console.err(&format!("{}", e));
            exit(1);
        });

    console.info(&format!(
        "Using {} to connect to {}",
        certificate_path, host
    ));

    // Start ssh
    let ssh_args = vec![&host[..], "-i", ssh_path, "-i", &certificate_path];
    let mut ssh_args: Vec<String> = ssh_args.iter().map(|x| String::from(*x)).collect();
    for arg in args {
        ssh_args.push(arg);
    }

    Command::new("ssh")
        .args(ssh_args)
        .stdout(std::process::Stdio::inherit())
        .stdin(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .output()?;
    Ok(())
}

/// Loads the configuration file in the following order
/// 1. config.toml in the current directory
/// 2. VSSH_CONFIG environment variable
/// 3. ~/.config/vault_ssh_helper.toml
fn get_config_path() -> Result<String> {
    fn file_exists(path: &str) -> bool {
        Path::new(path).exists()
    }

    if file_exists("vault_ssh_config.toml") {
        return Ok(String::from("vault_ssh_config.toml"));
    } else {
        let env_var_file = std::env::var("VSSH_CONFIG");
        match env_var_file {
            Ok(var) => {
                return if file_exists(&var) {
                    Ok(var)
                } else {
                    Err(anyhow!("Config file at {} not found", var))
                };
            }
            Err(_) => {
                let path = shellexpand::tilde("~/.config/vault_ssh_helper.toml").to_string();
                if file_exists(&path) {
                    return Ok(path);
                }
            }
        }
    }
    return Err(anyhow!("Config file not found"));
}
