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
static ARCHIVE_EXTENSIONS: &[&str] = &["jar", "war", "ear", "aar"];

/// Severity None
pub const SEVERITY_NONE: u8 = 0;

/// Severity Info
pub const SEVERITY_INFO: u8 = 1;

/// Severity Warn
pub const SEVERITY_WARN: u8 = 2;

/// Severity Error
pub const SEVERITY_ERROR: u8 = 3;

/// Signature for the fix of Log4j 2.12.2 (<https://github.com/apache/logging-log4j2/commit/70edc233343815d5efa043b54294a6fb065aa1c5#diff-4fde33b59714d0691a648fb2752ea1892502a815bdb40e83d3d6873abd163cdeR37>)
static SIGN_CVE202145046_FIX_2_12_2: &[&str] =
    &["JNDI is not supported", "CVE-2021-45046 (Log4j 2.12.2)"];

/// Signature for the fix of Log4j 2.12.3(Java 7) & 2.17.0 (Java 8)(<https://github.com/apache/logging-log4j2/commit/4a4b7530b1848e630a65d79e9c7dc388a5a7785b#diff-4fde33b59714d0691a648fb2752ea1892502a815bdb40e83d3d6873abd163cdeR48>)
static SIGN_CVE202145105_FIX: &[&str] = &[
    "JNDI must be enabled by setting log4j2.enableJndiLookup=true",
    "CVE-2021-45105 (Log4j 2.3.1, 2.12.3 or 2.17.0)",
];

/// Signature for the fix of Log4j 2.16 (<https://github.com/apache/logging-log4j2/commit/27972043b76c9645476f561c5adc483dec6d3f5d#diff-22ae074d2f9606392a3e3710b34967731a6ad3bc4012b42e0d362c9f87e0d65bR97>)
static SIGN_CVE202145046_FIX_V2_16: &[&str] = &[
    "Message Lookups are no longer supported",
    "CVE-2021-45046 (Log4j 2.16)",
];

/// Signature for the fix of CVE-2021-44832 in in Log4j 2.17.1 (Java 8), 2.12.4 (Java 7) and 2.3.2 (Java 6)
/// (<https://github.com/apache/logging-log4j2/compare/rel/2.17.0...rel/2.17.1#diff-7a4ee8038e15df37e26aec121d76968a09f90a9dfaee21baf2e8acb398b04c75R69>)
static SIGN_CVE202144832_FIX: &[&str] = &[
    "JNDI must be enabled by setting log4j2.enableJndiJdbc=true",
    "CVE-2021-44832 (Log4j 2.3.2, 2.12.4 or 2.17.1)",
];

/// Contains the result of the scan of a file.
pub struct ArchiveScanResult {
    // Flag to indicate if the archive still vulnerable despite identified fix
    pub vulnerable: bool,

    // Severity of the risk, if any
    pub severity: u8,

    // Flag to indicate if the jndi class been identified
    pub has_jndi_class: bool,
}

impl ArchiveScanResult {
    fn new() -> ArchiveScanResult {
        ArchiveScanResult {
            vulnerable: false,
            severity: SEVERITY_NONE,
            has_jndi_class: false,
        }
    }
}

/// Finds if the provided Vector of bytes contains the sequence of bytes of the provided string
fn find_signature_in_bytes(bytes: &[u8], signature: &str) -> bool {
    let finder = memmem::Finder::new(signature);

    finder.find(bytes) != None
}

/// Reads the file on the provided buffer
fn read_file_to_buffer(file: &mut ZipFile, buffer: &mut Vec<u8>) -> io::Result<usize> {
    // Reads the file content
    buffer.clear();
    buffer.reserve(file.size() as usize); // Reserve enough capacity to store all the file
    file.read_to_end(buffer)
}

/// Updates cumulated scan result after individual result
fn update_cumulated_result(
    cumulated_result: &mut ArchiveScanResult,
    subresult: &ArchiveScanResult,
) {
    cumulated_result.vulnerable = cumulated_result.vulnerable || subresult.vulnerable;
    if cumulated_result.severity < subresult.severity {
        cumulated_result.severity = subresult.severity;
    }
    cumulated_result.has_jndi_class = cumulated_result.has_jndi_class || subresult.has_jndi_class;
}

/// Processes an archive to find vulnerabilities
fn process_archive<R: Read + Seek>(
    read: R,
    paths: &[&str],
    args: &Cli,
) -> Result<ArchiveScanResult, std::io::Error> {
    trace!("Scanning archive {}", paths.join(" contains "));

    let reader = BufReader::new(read);

    // Zip archive
    let mut archive = zip::ZipArchive::new(reader)?;

    // Current archive scan result
    let mut result = ArchiveScanResult::new();

    // Cumulated result including result from nested archives
    let mut cumulated_result = ArchiveScanResult::new();

    // Consider the file vulnerable until proven otherwise.
    result.vulnerable = true;

    // Current archive scan has some fix
    let mut fixed = false;

    // Version of current archive scan has some fix
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

            let file_name = outpath.file_name().unwrap_or_else(|| OsStr::new(""));
            if file_name == JNDI_LOOKUP_CLASS_FILE {
                result.has_jndi_class = true;

                trace!(
                    "Found \"{}\" in \"{}\" ({} bytes)",
                    file.name(),
                    outpath.display(),
                    file.size()
                );

                read_file_to_buffer(&mut file, &mut buffer)?; // Load the file on the buffer
                if find_signature_in_bytes(&buffer, SIGN_CVE202145105_FIX[0]) {
                    if !fixed || fix_version != SIGN_CVE202144832_FIX[1] {
                        fix_version = SIGN_CVE202145105_FIX[1];
                    }
                    fixed = true;
                    trace!("Found {} signature", SIGN_CVE202145105_FIX[1]);
                } else if find_signature_in_bytes(&buffer, SIGN_CVE202145046_FIX_2_12_2[0]) {
                    fixed = true;
                    fix_version = SIGN_CVE202145046_FIX_2_12_2[1];
                    trace!("Found {} signature", SIGN_CVE202145046_FIX_2_12_2[1]);
                }
            } else if !fixed && file_name == MESSAGE_PATTERN_CLASS_FILE {
                // If not fixed look in other file´s signatures
                read_file_to_buffer(&mut file, &mut buffer)?; // Load the file on the buffer
                if find_signature_in_bytes(&buffer, SIGN_CVE202145046_FIX_V2_16[0]) {
                    fixed = true;
                    fix_version = SIGN_CVE202145046_FIX_V2_16[1];
                    trace!("Found {} signature", SIGN_CVE202145046_FIX_V2_16[1]);
                }
            } else if file_name == JDBC_PATTERN_CLASS_FILE {
                // If not fixed look in other file´s signatures
                read_file_to_buffer(&mut file, &mut buffer)?; // Load the file on the buffer
                if find_signature_in_bytes(&buffer, SIGN_CVE202144832_FIX[0]) {
                    fixed = true;
                    result.vulnerable = false;
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

                // Scan recursively and return the
                if is_archive_file {
                    trace!("Contains an archive {}", outpath.display());

                    let mut new_paths = paths.to_owned();
                    let path_str: String = outpath.to_string_lossy().to_string();
                    new_paths.push(&path_str);

                    // Reads the file content
                    buffer.clear();
                    buffer.reserve(file.size() as usize); // Reserve enough capacity to store all the file
                    file.read_to_end(&mut buffer)?;
                    let archive_data = Cursor::new(&buffer);

                    let subresult = process_archive(archive_data, &new_paths, args);

                    if let Ok(r) = subresult { update_cumulated_result(&mut cumulated_result, &r) }
                }
            }
        }
    }

    if result.has_jndi_class && fixed {
        if result.vulnerable {
            result.severity = SEVERITY_WARN;
            warn!(
                "{} seems to be fixed for {} but vulnerable to other CVE",
                paths.join(" contains "),
                fix_version
            )
        } else {
            result.severity = SEVERITY_INFO;
            info!(
                "{} seems to be fixed for {} and not vulnerable",
                paths.join(" contains "),
                fix_version
            )
        }
    } else if result.has_jndi_class {
        result.severity = SEVERITY_ERROR;
        error!(
            "{} seems vulnerable to critical CVE",
            paths.join(" contains ")
        );
    } else {
        result.severity = SEVERITY_NONE;
        result.vulnerable = false; // Not vulnerable
    }

    update_cumulated_result(&mut cumulated_result, &result);

    Ok(cumulated_result)
}

/// Processes a file from the filesystem to find vulnerabilities
fn process_file(path: &Path, args: &Cli) -> Result<ArchiveScanResult, std::io::Error> {
    if path.file_name().unwrap_or_else(|| OsStr::new("")) == JNDI_LOOKUP_CLASS_FILE {
        // If Jndi class is found outside an archive, consider vulnerable with warn severity
        let mut result = ArchiveScanResult::new();
        result.has_jndi_class = true;
        result.severity = SEVERITY_WARN;
        result.vulnerable = true;

        warn!(
            "{} is 'JndiLookup.class' and may be vulnerable",
            path.display()
        );

        return Ok(result);
    }

    match path.extension() {
        Some(extension) => {
            if is_archive(extension, args.scan_zip) {
                let file = fs::File::open(path)?;
                let mut paths: Vec<&str> = Vec::new();

                let path_str = &path.to_string_lossy();
                paths.push(path_str);
                return process_archive(&file, &paths, args);
            }
        }
        None => return Ok(ArchiveScanResult::new()),
    }
    Ok(ArchiveScanResult::new())
}

/// Identifies if the extension provided belongs to an archive to be analyzed
fn is_archive(extension: &OsStr, include_zip: bool) -> bool {
    // Check zip extension if enabled
    if include_zip && extension.eq_ignore_ascii_case("zip") {
        return true;
    }

    for archive_extension in ARCHIVE_EXTENSIONS {
        if extension.eq_ignore_ascii_case(archive_extension) {
            return true;
        }
    }

    false
}

/// Runs the scan
pub fn scan(args: &Cli) -> Result<u64, std::io::Error> {
    let mut count_dirs: u64 = 0;
    let mut count_files: u64 = 0;
    let mut count_vulnerable: u64 = 0; // Count number of vulnerable files

    // Scan all the matching files under the parent directory
    for e in WalkDir::new(&args.path)
        .follow_links(args.follow_links)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if e.metadata()?.is_file() {
            count_files += 1;
            trace!("Scanning file \"{}\"", e.path().display());
            match process_file(e.path(), args) {
                Ok(result) => {
                    if result.vulnerable {
                        count_vulnerable += 1;
                    }
                }
                Err(error) => {
                    info!("{} can´t be read. Error:{:?}", e.path().display(), error);
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

    info!("Found {} vulnerable files", count_vulnerable);

    Ok(count_vulnerable)
}

/// Test scans
#[cfg(test)]
mod scan_tests {
    use crate::log4shell_scanner::{
        process_file, scan, SEVERITY_ERROR, SEVERITY_INFO, SEVERITY_NONE, SEVERITY_WARN,
    };
    use std::path::PathBuf;

    /// Tests the scan of an archive against expected output
    fn test_archive(
        path: &str,
        _expected_severity: u8,
        _expected_has_jndi_class: bool,
        _expected_vulnerable: bool,
    ) {
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push(path);

        let path = d.as_path();

        let args = crate::cli::Cli {
            path: d.clone(),
            scan_zip: true,
            trace: false,
            silent: false,
            follow_links: true,
        };

        let result = process_file(&path, &args);

        match result {
            Ok(r) => {
                assert_eq!(r.has_jndi_class, _expected_has_jndi_class);
                assert_eq!(r.vulnerable, _expected_vulnerable);
                assert_eq!(r.severity, _expected_severity);
            }
            _ => (), // Ignore errors
        }
    }

    /// Tests the scan of an archive against expected output. Include zip files.
    fn test_scan(path: &str, _expected_vulnerabilities: u64) {
        test_scan_zip(path, _expected_vulnerabilities, true)
    }

    /// Tests the scan of an archive against expected output.
    fn test_scan_zip(path: &str, _expected_vulnerabilities: u64, scan_zip: bool) {
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push(path);

        let args = crate::cli::Cli {
            path: d.clone(),
            scan_zip: scan_zip,
            trace: false,
            silent: false,
            follow_links: true,
        };

        let result = scan(&args);

        match result {
            Ok(num) => {
                assert_eq!(num, _expected_vulnerabilities);
            }
            _ => (), // Ignore errors
        }
    }

    /// Test log4j-core-2.3 and earlier
    #[test]
    fn process_file_log4j_core_2_3_and_older() {
        test_archive(
            "resources/test/log4j-core-2.2.jar",
            SEVERITY_ERROR,
            true,
            true,
        );
        test_archive(
            "resources/test/log4j-core-2.1.jar",
            SEVERITY_ERROR,
            true,
            true,
        );
        test_archive(
            "resources/test/log4j-core-2.0.jar",
            SEVERITY_ERROR,
            true,
            true,
        );
        test_archive(
            "resources/test/log4j-core-2.3.jar",
            SEVERITY_ERROR,
            true,
            true,
        );
    }

    /// Test log4j-core-2.15 and earlier excluding fixed 2.12.x
    #[test]
    fn process_file_log4j_core_2_15_and_older() {
        test_archive(
            "resources/test/log4j-core-2.14.1.jar",
            SEVERITY_ERROR,
            true,
            true,
        );
        test_archive(
            "resources/test/log4j-core-2.15.0.jar",
            SEVERITY_ERROR,
            true,
            true,
        );
        test_archive(
            "resources/test/log4j-core-2.12.1.jar",
            SEVERITY_ERROR,
            true,
            true,
        );
    }

    /// Test log4j-core-2.16.0, 2.12.2 fixing CVE202145046
    #[test]
    fn process_file_log4j_core_cve202145046_fix() {
        test_archive(
            "resources/test/log4j-core-2.16.0.jar",
            SEVERITY_WARN,
            true,
            true,
        );
        test_archive(
            "resources/test/log4j-core-2.12.2.jar",
            SEVERITY_WARN,
            true,
            true,
        );
    }

    /// Test log4j-core-2.17.0, 2.12.3, 2.3.1 fixing CVE202145105
    #[test]
    fn process_file_log4j_core_cve202145105_fix() {
        test_archive(
            "resources/test/log4j-core-2.17.0.jar",
            SEVERITY_WARN,
            true,
            true,
        );
        test_archive(
            "resources/test/log4j-core-2.12.3.jar",
            SEVERITY_WARN,
            true,
            true,
        );
        test_archive(
            "resources/test/log4j-core-2.3.1.jar",
            SEVERITY_WARN,
            true,
            true,
        );
    }

    /// Test log4j-core-2.17.1, 2.12.4, 2.3.2 fixing CVE202144832
    /// Only versions with no vulnerabilities.
    #[test]
    fn process_file_log4j_core_cve202144832_fix() {
        test_archive(
            "resources/test/log4j-core-2.17.1.jar",
            SEVERITY_INFO,
            true,
            false,
        );
        test_archive(
            "resources/test/log4j-core-2.12.4.jar",
            SEVERITY_INFO,
            true,
            false,
        );
        test_archive(
            "resources/test/log4j-core-2.3.2.jar",
            SEVERITY_INFO,
            true,
            false,
        );
    }

    /// Not archives
    #[test]
    fn process_file_not_archive() {
        test_archive(
            "resources/test/fake/fake-archive.jar",
            SEVERITY_NONE,
            false,
            false,
        );
        test_archive(
            "resources/test/fake/simplefile.txt",
            SEVERITY_NONE,
            false,
            false,
        );
    }

    /// Nested
    #[test]
    fn process_file_nested_jar() {
        test_archive(
            "resources/test/myvulnerablejar.Jar",
            SEVERITY_ERROR,
            true,
            true,
        );
    }

    /// Nested
    #[test]
    fn process_file_nested_zip() {
        test_archive(
            "resources/test/myvulnerablejar.ZIP",
            SEVERITY_ERROR,
            true,
            true,
        );
    }

    /// Uber jar
    #[test]
    fn process_file_uber_jar() {
        test_archive(
            "resources/test/uberjar/infinispan-embedded-query-8.2.12.Final.jar",
            SEVERITY_ERROR,
            true,
            true,
        );
    }

    /// Exploded class
    #[test]
    fn process_exploded_file() {
        test_archive( // Vulnerable
            "resources/test/resources/test/exploded_extract/log4j-core-2.14.1/org/apache/logging/log4j/core/lookup/JndiLookup.class",
            SEVERITY_WARN,
            true,
            true,
        );
        test_archive( // Not vulnerable
            "resources/test/resources/test/exploded_extract/log4j-core-2.14.1/org/apache/logging/log4j/core/lookup/Log4jLookup.class",
            SEVERITY_NONE,
            false,
            false,
        );
    }

    /// Scan specific file
    #[test]
    fn scan_file() {
        test_scan("resources/test/log4j-core-2.14.1.jar", 1);
    }

    /// Test zip flag
    #[test]
    fn scan_zip() {
        // If flag is on, zip is scanned
        test_scan_zip("resources/test/myvulnerablejar.ZIP", 1, true);

        // If flag is off, zip is not scanned
        test_scan_zip("resources/test/myvulnerablejar.ZIP", 0, false);
    }

    /// Scan specific folder
    #[test]
    fn scan_folder() {
        test_scan("resources/test/uberjar", 1);
        test_scan("resources/test/fake", 0);
    }

    /// Scan folder with exploded jar
    #[test]
    fn scan_exploded() {
        test_scan("resources/test/exploded_extract/log4j-core-2.14.1", 1);
    }
}
