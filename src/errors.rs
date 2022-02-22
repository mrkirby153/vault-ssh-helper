use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Configuration parse failed")]
    ConfigParseError {
        source: toml::de::Error
    },
    #[error("Configuration file not found")]
    ConfigNotFoundError {
        path: String
    },
    #[error("An I/O error occurred")]
    IOError {
        #[from]
        source: std::io::Error
    },
}