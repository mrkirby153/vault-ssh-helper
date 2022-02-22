use std::error::Error;

use vault_ssh_helper::load_config;

fn main() -> Result<(), Box<dyn Error>> {
    let config = load_config("config.toml")?;
    println!("Config: {:?}", config);
    Ok(())
}
