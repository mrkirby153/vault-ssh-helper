use std::error::Error;
use std::process::exit;

use vault_ssh_helper::console::{ColorConsole, Console};
use vault_ssh_helper::load_config;
use vault_ssh_helper::vault::get_vault_client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let console: Box<dyn Console> = Box::new(ColorConsole::new());
    let console = console.as_ref();

    // Load the config
    let config = load_config("config.toml")?;
    console.info("Checking vault token...");
    // Check if the vault token is valid
    let client = match get_vault_client(&config).await {
        Ok(client) => {
            console.success("Ok!");
            client
        }
        Err(e) => {
            console.err(&*format!("Error: {}", e));
            exit(1);
        }
    };
    // Check if the ssh keyfile exists
    let ssh_path = match config.identity.as_ref() {
        Some(t) => t,
        None => {
            console.err("Identity file not specified");
            exit(1);
        }
    };
    console.info(&*format!("Attempting to connect with ssh key {}...", ssh_path));
    if let Err(e) = vault_ssh_helper::ssh::check_ssh_file(&ssh_path[..]) {
        console.err(&format!("Error: {}", e)[..])
    }
    // Get the signed key (if present)
    // If the signed key is not present, generate one
    // Spawn a ssh command
    Ok(())
}
