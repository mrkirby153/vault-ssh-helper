use console::Style;

pub trait Console {
    /// Logs an info message
    fn info(&self, message: &str);
    /// Logs a warning message
    fn warn(&self, message: &str);
    /// Logs an error message
    fn err(&self, message: &str);
    /// Logs a success message
    fn success(&self, message: &str);
}

/// A console that outputs colored text
pub struct ColorConsole {
    info: Style,
    warn: Style,
    err: Style,
    success: Style,
}

/// A console that only outputs plain text
pub struct PlainConsole;

impl ColorConsole {
    pub fn new() -> ColorConsole {
        ColorConsole {
            info: Style::new().white().bold().bright(),
            warn: Style::new().yellow().bold().bright(),
            err: Style::new().red().bold().bright(),
            success: Style::new().green().bold().bright(),
        }
    }
}

impl Console for ColorConsole {
    fn info(&self, message: &str) {
        println!("{}", self.info.apply_to(message))
    }

    fn warn(&self, message: &str) {
        println!("{}", self.warn.apply_to(message))
    }

    fn err(&self, message: &str) {
        println!("{}", self.err.apply_to(message))
    }

    fn success(&self, message: &str) {
        println!("{}", self.success.apply_to(message))
    }
}

impl Console for PlainConsole {
    fn info(&self, message: &str) {
        println!("{}", message)
    }

    fn warn(&self, message: &str) {
        println!("{}", message)
    }

    fn err(&self, message: &str) {
        println!("{}", message)
    }

    fn success(&self, message: &str) {
        println!("{}", message)
    }
}