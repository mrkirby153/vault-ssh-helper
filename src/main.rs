use std::error::Error;
use std::process::exit;

use vault_ssh_helper::{get_vault_client, load_config};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Load the config
    let config = load_config("config.toml")?;
    // Check if the vault token is valid
    let client = get_vault_client(&config).await?;
    // Check if the ssh keyfile exists
    // Get the signed key (if present)
    // If the signed key is not present, generate one
    // Spawn a ssh command
    Ok(())
}
