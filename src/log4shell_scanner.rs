#![warn(missing_docs)]

use crate::cli::Cli;
use log::{error, info, warn};
use memchr::memmem;
use std::ffi::OsStr;
use std::io::{BufReader, Cursor, Read, Seek};
use std::path::Path;
use std::{fs, io};
use walkdir::WalkDir;
use zip::read::ZipFile;

// Constants

/// Name of the JndiLookup class file used to identify the presence of log4j 2.x
const JNDI_LOOKUP_CLASS_FILE: &str = "JndiLookup.class";

/// Name of the MessagePatternConverter class file used to identify the version of log4j 2.x
const MESSAGE_PATTERN_CLASS_FILE: &str = "MessagePatternConverter.class";

/// Name of the MessagePatternConverter class file used to identify the version of log4j 2.x
const JDBC_PATTERN_CLASS_FILE: &str = "DataSourceConnectionSource.class";

/// Default extensions of files to be scanned
static ARCHIVE_EXTENSIONS: &'static [&str] = &["jar", "war", "ear", "aar"];

/// Signature for the fix of Log4j 2.12.2 (<https://github.com/apache/logging-log4j2/commit/70edc233343815d5efa043b54294a6fb065aa1c5#diff-4fde33b59714d0691a648fb2752ea1892502a815bdb40e83d3d6873abd163cdeR37>)
static SIGN_CVE202145046_FIX_2_12_2: &'static [&str] =
    &["JNDI is not supported", "CVE-2021-45046 (Log4j 2.12.2)"];

/// Signature for the fix of Log4j 2.12.3(Java 7) & 2.17.0 (Java 8)(<https://github.com/apache/logging-log4j2/commit/4a4b7530b1848e630a65d79e9c7dc388a5a7785b#diff-4fde33b59714d0691a648fb2752ea1892502a815bdb40e83d3d6873abd163cdeR48>)
static SIGN_CVE202145105_FIX: &'static [&str] = &[
    "JNDI must be enabled by setting log4j2.enableJndiLookup=true",
    "CVE-2021-45105 (Log4j 2.3.1, 2.12.3 or 2.17.0)",
];

/// Signature for the fix of Log4j 2.16 (<https://github.com/apache/logging-log4j2/commit/27972043b76c9645476f561c5adc483dec6d3f5d#diff-22ae074d2f9606392a3e3710b34967731a6ad3bc4012b42e0d362c9f87e0d65bR97>)
static SIGN_CVE202145046_FIX_V2_16: &'static [&str] = &[
    "Message Lookups are no longer supported",
    "CVE-2021-45046 (Log4j 2.16)",
];

/// Signature for the fix of CVE-2021-44832 in in Log4j 2.17.1 (Java 8), 2.12.4 (Java 7) and 2.3.2 (Java 6)
/// (<https://github.com/apache/logging-log4j2/compare/rel/2.17.0...rel/2.17.1#diff-7a4ee8038e15df37e26aec121d76968a09f90a9dfaee21baf2e8acb398b04c75R69>)
static SIGN_CVE202144832_FIX: &'static [&str] = &[
    "JNDI must be enabled by setting log4j2.enableJndiJdbc=true",
    "CVE-2021-44832 (Log4j 2.3.2, 2.12.4 or 2.17.1)",
];

/// Finds if the provided Vector of bytes contains the sequence of bytes of the provided string
fn find_signature_in_bytes(bytes: &Vec<u8>, signature: &str) -> bool {
    let finder = memmem::Finder::new(signature);

    if finder.find(bytes) != None {
        return true;
    } else {
        return false;
    }
}

/// Reads the file on the provided buffer
fn read_file_to_buffer(file: &mut ZipFile, buffer: &mut Vec<u8>) -> io::Result<usize> {
    // Reads the file content
    buffer.clear();
    buffer.reserve(file.size() as usize); // Reserve enough capacity to store all the file
    file.read_to_end(buffer)
}

/// Processes an archive to find vulnerabilities
fn process_archive<R: Read + Seek>(read: R, paths: &Vec<&str>, args: &Cli) -> io::Result<()> {
    trace!("Scanning archive {}", paths.join(" contains "));

    let reader = BufReader::new(read);

    // Zip archive
    let mut archive = zip::ZipArchive::new(reader)?;

    // The scanned version has fixed some vulnerability
    let mut fixed = false;

    // Flag to indicate if the archive still vulnerable
    let mut vulnerable = true;

    // Flag to indicate if the jndi class been identified
    let mut has_jndi_class = false;

    // Version that has the identified fix
    let mut fix_version = "";

    // Buffer to read files content
    let mut buffer: Vec<u8> = Vec::new();

    // Scan each directory or file in the archive
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;

        let outpath = match file.enclosed_name() {
            Some(path) => path,
            None => {
                trace!("Entry {} has a suspicious path", file.name());
                continue;
            }
        };

        if file.is_file() {
            // Element is file

            let file_name = outpath.file_name().unwrap_or(OsStr::new(""));
            if file_name == JNDI_LOOKUP_CLASS_FILE {
                has_jndi_class = true;

                trace!(
                    "Found \"{}\" in \"{}\" ({} bytes)",
                    file.name(),
                    outpath.display(),
                    file.size()
                );

                read_file_to_buffer(&mut file, &mut buffer)?; // Load the file on the buffer
                if find_signature_in_bytes(&mut buffer, SIGN_CVE202145105_FIX[0]) {
                    if !fixed || fix_version != SIGN_CVE202144832_FIX[1]{
                        fix_version = SIGN_CVE202145105_FIX[1];
                    }
                    fixed = true;
                    trace!("Found {} signature", SIGN_CVE202145105_FIX[1]);
                } else if find_signature_in_bytes(&mut buffer, SIGN_CVE202145046_FIX_2_12_2[0]) {
                    fixed = true;
                    fix_version = SIGN_CVE202145046_FIX_2_12_2[1];
                    trace!("Found {} signature", SIGN_CVE202145046_FIX_2_12_2[1]);
                }
            } else if !fixed && file_name == MESSAGE_PATTERN_CLASS_FILE {
                // If not fixed look in other file´s signatures
                read_file_to_buffer(&mut file, &mut buffer)?; // Load the file on the buffer
                if find_signature_in_bytes(&mut buffer, SIGN_CVE202145046_FIX_V2_16[0]) {
                    fixed = true;
                    fix_version = SIGN_CVE202145046_FIX_V2_16[1];
                    trace!("Found {} signature", SIGN_CVE202145046_FIX_V2_16[1]);
                }
            } else if file_name == JDBC_PATTERN_CLASS_FILE {
                // If not fixed look in other file´s signatures
                read_file_to_buffer(&mut file, &mut buffer)?; // Load the file on the buffer
                if find_signature_in_bytes(&mut buffer, SIGN_CVE202144832_FIX[0]) {
                    fixed = true;
                    vulnerable = false;
                    fix_version = SIGN_CVE202144832_FIX[1];
                    trace!("Found {} signature", SIGN_CVE202144832_FIX[1]);
                }
            } else {
                // Recursively scan if the file is an archive
                let mut is_archive_file = false;

                match outpath.extension() {
                    Some(extension) => {
                        if is_archive(extension, args.scan_zip) {
                            is_archive_file = true;
                        }
                    }
                    None => (),
                }

                if is_archive_file {
                    trace!("Contains an archive {}", outpath.display());

                    let mut new_paths = paths.clone();
                    let path_str: String = outpath.to_string_lossy().to_string();
                    new_paths.push(&path_str);

                    // Reads the file content
                    buffer.clear();
                    buffer.reserve(file.size() as usize); // Reserve enough capacity to store all the file
                    file.read_to_end(&mut buffer)?;
                    let archive_data = Cursor::new(&buffer);

                    process_archive(archive_data, &new_paths, &args).ok();
                }
            }
        }
    }

    if has_jndi_class && fixed {
        if vulnerable {
            warn!(
                "{} seems to be fixed for {} but vulnerable to other CVE",
                paths.join(" contains "),
                fix_version
            )
        } else {
            info!(
                "{} seems to be fixed for {} and not vulnerable",
                paths.join(" contains "),
                fix_version
            )
        }
    } else if has_jndi_class {
        error!(
            "{} seems vulnerable to critical CVE",
            paths.join(" contains ")
        );
    }

    Ok(())
}

/// Processes a file from the filesystem to find vulnerabilities
fn process_file(path: &Path, args: &Cli) -> io::Result<()> {
    if path.file_name().unwrap_or(OsStr::new("")) == JNDI_LOOKUP_CLASS_FILE {
        warn!(
            "{} is 'JndiLookup.class' and may be vulnerable",
            path.display()
        );
    }

    match path.extension() {
        Some(extension) => {
            if is_archive(extension, args.scan_zip) {
                let file = fs::File::open(path)?;
                let mut paths: Vec<&str> = Vec::new();

                let path_str = &path.to_string_lossy();
                paths.push(path_str);
                return process_archive(&file, &paths, &args);
            }
        }
        None => return Ok(()),
    }
    Ok(())
}

/// Identifies if the extension provided belongs to an archive to be analyzed
fn is_archive(extension: &OsStr, include_zip: bool) -> bool {
    // Check zip extension if enabled
    if include_zip && extension.eq_ignore_ascii_case("zip") {
        return true;
    }

    for i in 0..ARCHIVE_EXTENSIONS.len() {
        if extension.eq_ignore_ascii_case(ARCHIVE_EXTENSIONS[i]) {
            return true;
        }
    }

    return false;
}

/// Runs the scan
pub fn scan(args: &Cli) -> io::Result<()> {
    let mut count_dirs: u64 = 0;
    let mut count_files: u64 = 0;
    //let mut count_vulnerable = 0;

    // Scan all the matching files under the parent directory
    for e in WalkDir::new(&args.path)
        .follow_links(args.follow_links)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if e.metadata()?.is_file() {
            count_files += 1;
            trace!("Scanning file \"{}\"", e.path().display());
            match process_file(e.path(), &args) {
                Ok(()) => (),
                Err(error) => {
                    info!("{} can´t be read. Error:{:?}", e.path().display(), error)
                }
            };
        } else {
            count_dirs += 1;
            trace!("Scanning directory \"{}\"", e.path().display());
        }
    }

    info!(
        "Scanned {} directories and {} files",
        count_dirs, count_files
    );

    Ok(())
}
