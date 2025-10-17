#![warn(missing_docs)]
#![crate_name = "log4shell_scanner_rs"]

//! Utility to scan files on the FIleSystem and detect potential vulnerabilities to Log4Shell.

use env_logger::{Builder, Env, Target};
use std::io::Write;
use std::time::Instant;
use clap::Parser;

mod cli;
mod log4shell_scanner;

#[macro_use]
extern crate log;

/// Get the severity level to used based on the CLI arguments.
/// By default the severity level is info.
/// If the trace argument is passed, the severity level is trace.
/// If the silent argument is passed, the severity level is warn.
fn get_log_severity_level(args: &cli::Cli) -> &str {
    let mut log_level = "info";

    if args.trace {
        log_level = "trace";
    } else if args.silent {
        log_level = "warn";
    }

    log_level
}

/// Initializes log
fn init_log(severity_level: &str) {
    let env = Env::default().filter_or("LOG_LEVEL", severity_level);

    let mut builder = Builder::from_env(env);
    builder.target(Target::Stdout);

    builder.format(|buf, record| {
        let timestamp = buf.timestamp();

        writeln!(
            buf,
            "{}\t{}\t{}",
            timestamp,
            record.level(),
            record.args()
        )
    });

    builder.init();
}

/// Entry point of the application
fn main() {
    let now = Instant::now();
    let args = cli::Cli::parse();

    // Initialize log
    init_log(get_log_severity_level(&args));

    info!("log4shell-scanner-rs scanning {}", args.path.display());

    log4shell_scanner::scan(&args).ok();

    info!("Completed in {} milliseconds", now.elapsed().as_millis());
}
