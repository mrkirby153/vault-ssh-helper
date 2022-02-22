use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Configuration parse failed")]
    ConfigParseError {
        source: toml::de::Error
    },
    #[error("An I/O error occurred")]
    IOError {
        #[from]
        source: std::io::Error
    },
    #[error("Missing argument: {name:?}")]
    MissingArgumentError {
        name: String,
    }
}