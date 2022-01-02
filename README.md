# Log4Shell Scanner

[![Build Status](https://travis-ci.com/yannart/log4shell-scanner-rs.svg?branch=main)](https://travis-ci.com/yannart/log4shell-scanner-rs)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Minimum rustc version](https://img.shields.io/badge/rustc-v1.57.0-lightgray.svg)](https://blog.rust-lang.org/2021/12/02/Rust-1.57.0.html)

Log4Shell Scanner (`log4shell-scanner-rs`) is a CLI application written in [Rust](https://www.rust-lang.org/). It scans the file system to find Java applications that may be vulnerable to [Log4Shell](https://en.wikipedia.org/wiki/Log4Shell) related vulnerabilities ([CVE-2021-44228](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228), [CVE-2021-45046](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45046), [CVE-2021-45105](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45105), [CVE-2021-44832](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44832)).

Detail of Log4Shell [vulnerabilities](https://logging.apache.org/log4j/2.x/security.html) affecting Log4j2:
| CVE                                                                             | Severity | Fix version (min Java version)                            |
|---------------------------------------------------------------------------------|----------|-----------------------------------------------------------|
| [CVE-2021-44832](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44832) | Moderate | Log4j 2.17.1 (Java 8), 2.12.4 (Java 7) and 2.3.2 (Java 6) |
| [CVE-2021-45105](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45105) | Moderate | Log4j 2.17.0 (Java 8), 2.12.3 (Java 7) and 2.3.1 (Java 6) |
| [CVE-2021-45046](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45046) | Critical | Log4j 2.16.0 (Java 8) and Log4j 2.12.2 (Java 7)           |
| [CVE-2021-44228](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228) | Critical | Log4j 2.15.0 (Java 8)                                     |

## Features
* Supports nested Java archives and different type of `jar` packaging (eg. war, zip, shaded jars, uber jars, spring-boot executable jars, jars inside jars, exploded jars).
* Uses file signatures instead of relying on specific file path or metadata.
* Single binary with no dependencies (eg. no Python, JVM nor PowerShell required) allows an easy portability to systems to be tested or allows to be embedded in container images.
* Improved execution time and reduced memory footprint thanks to native implementation in [Rust](https://www.rust-lang.org/). 

Note: This application is not intended to replace other Log4Shell scanners provided by agencies, Universities or cybersecurity companies but to complement them.

## How Does It Work?
Log4Shell Scanner scans recursively subdirectories and Java archives under the provided root directory. If the file `JndiLookup.class` is found it will look for file signatures to detect if it is a potentially vulnerable version of log4j or a fixed version. 
It supports scanning archives `jar`, `war`, `ear`, `aar` and `zip` including nested ones.

## Installation
Binaries are stored on the [Releases](https://github.com/yannart/log4shell-scanner-rs/releases) section.
Download the binary that matches your architecture and os, for example:
* `log4shell-scanner-rs-[version]-amd64-linux` for Linux OS on AMD64 bits architecture
* `log4shell-scanner-rs-[version]-amd64-osx` for Mac OS on AMD64 bits architecture
* `log4shell-scanner-rs-[version]-amd64-windows.exe` for Windows on AMD64 bits architecture

The file can be installed on the location of your choice. You may want to rename it to `log4shell-scanner-rs` for Linux or OSX or `log4shell-scanner-rs.exe` for Windows and/or create a symlink. The following instructions assume that the file has been renamed.

For Linux, MacOS you may need to set the executable access permissions, for example with the command:
`chmod +x log4shell-scanner-rs`

Note: The binaries are built automatically by the CI system [travis](https://travis-ci.org/). Checksums are provided to verify the files integrity.

## Usage
`log4shell-scanner-rs` needs to be run from a terminal.

By default only the archives with extensions `jar`, `war`, `ear` and `aar` are included but `zip` files are excluded. To include Zip files, add the flag `-z` or `--scan-zip`.

### CLI execution

To run the scanner, you need to provide at minimum the path of root folder to scan:
`log4shell-scanner-rs <path>`

Example: `log4shell-scanner-rs /home/me/`

Additional Flags allow to configure the execution (pass the flag `--help` to show the details eg.`log4shell-scanner-rs.exe --help`):

```
USAGE:
    log4shell-scanner-rs [FLAGS] <path>

FLAGS:
    -f, --follow-links    Follow follow_links
    -h, --help            Prints help information
    -z, --scan-zip        Scan also .zip extension files. This option may slow down scanning
    -s, --silent          Print only the scan results with a WARN or ERROR
    -t, --trace           Print all directories and files while scanning and enable log traces
    -V, --version         Prints version information

ARGS:
    <path>    The path to scan
```

### Output

The CLI will output in [tsv format](https://en.wikipedia.org/wiki/Tab-separated_values) the details of the files identified to have a version of Log4j2 potentially vulnerable.
Output logs severity:
* `ERROR`: Contains a file indicating a Log4j version vulnerable to a critical Log4Shell CVE.
* `WARN`:Contains a file indicating a Log4j version not vulnerable to a critical Log4Shell CVE but to a lower severity Log4Shell CVE.
* `INFO`: Contains a file indicating a Log4j version that seems not vulnerable to Log4Shell. Informational messages or files not read are reported with this severity.
* `TRACE`: Trace messages including all scanned directories and files.

### Output example
```
2021-12-25T19:25:02Z    INFO    log4shell-scanner-rs scanning /home/me/
2021-12-25T19:25:02Z    WARN    /home/me/log4j-core-2.12.2.jar seems to be fixed for CVE-2021-45046 (Log4j 2.12.2) but vulnerable to other CVE
2021-12-25T19:25:02Z    WARN    /home/me/log4j-core-2.12.3/org/apache/logging/log4j/core/lookup/JndiLookup.class is 'JndiLookup.class' and may be vulnerable
2021-12-25T19:25:02Z    WARN    /home/me/log4j-core-2.12.3.jar seems to be fixed for CVE-2021-45105 (Log4j 2.3.1, 2.12.3 or 2.17.0) but vulnerable to other CVE
2021-12-25T19:25:02Z    ERROR   /home/me/log4j-core-2.14.1.jar seems vulnerable to critical CVE
2021-12-25T19:25:02Z    ERROR   /home/me/log4j-core-2.15.0.jar seems vulnerable to critical CVE
2021-12-25T19:25:02Z    WARN    /home/me/log4j-core-2.17.0.jar seems to be fixed for CVE-2021-45046 (Log4j 2.16) but vulnerable to other CVE
2021-12-25T19:25:02Z    INFO    /home/me/log4j-core-2.17.1.jar seems to be fixed for CVE-2021-44832 (Log4j 2.3.2, 2.12.4 or 2.17.1) and not vulnerable
2021-12-25T19:25:02Z    WARN    /home/me/log4j-core-2.3.1.jar seems to be fixed for CVE-2021-45105 (Log4j 2.3.1, 2.12.3 or 2.17.0) but vulnerable to other CVE
2021-12-25T19:25:02Z    INFO    /home/me/log4j-core-2.3.2.jar seems to be fixed for CVE-2021-44832 (Log4j 2.3.2, 2.12.4 or 2.17.1) and not vulnerable
2021-12-25T19:25:02Z    ERROR   /home/me/log4j-core-2.3.jar seems vulnerable to critical CVE
2021-12-25T19:25:02Z    ERROR   /home/me/myvulnerablejar.Jar contains log4j-core-2.14.1.jar seems vulnerable to critical CVE
2021-12-25T19:25:02Z    WARN    /home/me/JndiLookup.class is 'JndiLookup.class' and may be vulnerable
2021-12-25T19:25:02Z    INFO    Scanned 284 directories and 3165 files
2021-12-25T19:25:02Z    INFO    Found 10 vulnerable files
2021-12-25T19:25:02Z    INFO    Completed in 407 milliseconds
```

## Build or Run from Source
log4shell-scanner-rs is built with [cargo](https://doc.rust-lang.org/cargo/). 

Prerequisites:
* [Install Rust and Cargo](https://www.rust-lang.org/tools/install)
* Clone this repository

### Build
To build it from the sources, run the following command:
```
cargo build --release
```
The binary is created under the subfolder `target`.

### Run from Source
Alternatively the scanner can be run directly from cargo:
```
cargo run --release -- [FLAGS] <path>
```

Example, command to scan the folder `/` including zip files:
```
cargo run --release -- -z /
```

## Testing
log4shell-scanner-rs has been tested against different type of Java archives (eg. war, zip, shaded jars, uber jars, spring-boot executable jars, jars inside jars, exploded jars).
Automated tests included and run against files under `resources/test`.

## Known limitations and future improvements
* If the file `JndiLookup.class` is found outside an archive, vulnerability fix signatures are not identified but it is considered vulnerable and a WARN message is printed.
* Archive with different extensions than the predefined list are ignored.
* A single parent folder can be provided. No exclusion patterns are possible.
* Not able to fix the archive potentially vulnerable.
* Code style improvements to be done and generalize the identification of vulnerability fix signatures.

## Copyright and license
Released under the [MIT license](LICENSE).
