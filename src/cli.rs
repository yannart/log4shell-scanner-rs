#![warn(missing_docs)]

use structopt::StructOpt;

/// Scans the file system to find Log4Shell vulnerabilities.
#[derive(StructOpt)]
pub struct Cli {
    /// The path to scan
    #[structopt(parse(from_os_str))]
    pub path: std::path::PathBuf,

    /// Scan also .zip extension files. This option may slow down scanning.
    #[structopt(short = "z", long)]
    pub scan_zip: bool,

    /// Print all directories and files while scanning and enable log traces.
    #[structopt(short, long)]
    pub trace: bool,

    /// Print only the scan results with a WARN or ERROR.
    #[structopt(short, long)]
    pub silent: bool,

    /// Follow follow_links.
    #[structopt(short, long)]
    pub follow_links: bool,
}
