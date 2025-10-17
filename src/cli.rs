#![warn(missing_docs)]

use clap::Parser;

/// Scans the file system to find Log4Shell vulnerabilities.
#[derive(Parser)]
pub struct Cli {
    /// The path to scan
    pub path: std::path::PathBuf,

    /// Scan also .zip extension files. This option may slow down scanning.
    #[arg(short = 'z', long)]
    pub scan_zip: bool,

    /// Print all directories and files while scanning and enable log traces.
    #[arg(short, long)]
    pub trace: bool,

    /// Print only the scan results with a WARN or ERROR.
    #[arg(short, long)]
    pub silent: bool,

    /// Follow follow_links.
    #[arg(short, long)]
    pub follow_links: bool,
}
