use std::error::Error;

use vault_ssh_helper::load_config;

fn main() -> Result<(), Box<dyn Error>> {
    // Load the config
    let config = load_config("config.toml")?;
    println!("Config: {:?}", config);
    // Check if the vault token is valid
    // Check if the ssh keyfile exists
    // Get the signed key (if present)
    // If the signed key is not present, generate one
    // Spawn a ssh command
    Ok(())
}
