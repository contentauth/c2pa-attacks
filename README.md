# C2PA Attacks

- [Overview](#overview)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Install c2pa-attacks](#install-c2pa-attacks)
  - [Updating](#updating)
- [Testing locally in the Git directory](#testing-locally-in-the-git-directory)
- [Directory layout](#directory-layout)
  - [Sample directory](#sample-directory)
- [Supported file formats](#supported-file-formats)
- [Examples](#examples)
  - [Inject into the author field using direct substitution](#inject-into-the-author-field-from-attack-file)
  - [Inject into the author field using regex substitution](#inject-into-the-author-field-using-regex-substitution)
- [Testing Certificate Authority fields](#testing-certificate-authority-fields)
  - [Inspecting the created files](#inspecting-the-created-files)

## Overview

The C2PA Attacks Tool performs security testing on a Content Credentials application (an application that uses the CAI SDKs and tools). The tool generates images with associated C2PA manifest stores to test the application for security vulnerabilities such as cross-site scripting. It takes a file of attack strings, adds each string into the designated manifest field, and produces a corresponding malicious C2PA image for testing. The tool does not automatically check to see if the attack was successful.

This tool facilitates security testing early in the development cycle of Content Credentials applications. For such applications, often the first step in processing an asset is to validate the signature and reject any whose public key is not from a trusted CA. That said, it is still good to test the parsers since hackers could find ways to get unexpected data into C2PA manfiest fields. In addition, it is conceivable that a Content Credentials application could parse manifest data without validating the certificate. Therefore, it is critical that the application safely handles unexpected input.

Each Content Credentials application has its own unique behavior and technology stack. Therefore, this tool provides a framework that you can customize for your specific needs.  The files provided with this tool are examples for initial experimentation. You will need to create customized attack files for your specific environment. Refer to the [appendix](docs/appendix.md) for information on how to cover more file types, more injections, and other forms of code coverage.

NOTE: This tool is a modification of the open-source C2PA [c2patool](https://github.com/contentauth/c2patool), but is not a replacement for it. The c2patool contains much more functionality and is a companion for this tool during analysis and testing.

## Installation

### Prerequisites

Install [Rust](https://www.rust-lang.org/tools/install). 

To use the tool, you also must have certificates for signing the content. 

### Install c2pa-attacks

Enter this command to install or update the tool:

```shell
cargo install c2pa-attacks
```

### Updating

To ensure you have the latest version, enter this command:

```
c2pa-attacks -V 
```

The tool will display the version installed. Compare the version number displayed with the latest release version shown in the [repository releases page](https://github.com/contentauth/c2patool/releases). To update to the latest version, reinstall the tool using the command shown above.

## Testing locally in the Git directory

If you just want to do local testing builds, then you can specify the make command followed by your corresponding OS platform. If you are using linux or the Windows Subsystem for Linux (WSL), then you will need development utilities such as `make` and `build-essential` already installed. To build c2pa-attacks, refer to the Makefile to identify the OS platform options for your environment:

```shell
rm -rf ./target/*
make build-release-{YOUR_OS_PLATFORM}-{YOUR_CPU}
./target/{YOUR_OS_PLATFORM}/release/c2pa-attacks
```

## Directory layout

The tool's directory layout is:

- `src` contains the tool's source code. 
- `docs` contains documentation. 
- `attacks` contains example files that can be used as the basis for injection attacks.  See the [README](./attacks/README.md) in that directory for details.
- `sample` contains example certificates and signing keys, example manifest files that reference them, and other related example files.

Your target application may not recognize the example certificates. If so, you can generate your own certificates from an approved CA for your platform and then use them as described in the [Appendix](docs/appendix.md#creating-and-using-an-x.509-certificate). The [C2PA technical specification](https://c2pa.org/specifications/specifications/1.3/specs/C2PA_Specification.html#_certificate_profile) describes requirements for signing certificates. 

### Sample directory 

The `sample` directory contains 

- `malicious_certificate.key` and `malicious_certificate.pem` - A certificate / key pair with random characters in the common name, organization, and organizational unit fields for testing a certificate parser's capability to handle unexpected characters. These are from a self-signed CA, so they will not work on an environment that enforces a trusted CA list.
- `malicious_certificate.json` - A manifest that is the same as `test.json` except that it specifies to use the malicious certificates for signing.

## Supported file formats

The tool works with the following types of asset files (also referred to as _assets_).

| MIME type                           | extensions  | read only |
| ----------------------------------- | ----------- | --------- |
| `image/jpeg`                        | `jpg, jpeg` |           |
| `image/png`                         | `png`       |           |
| `image/avif`                        | `avif`      |    X      |
| `image/heic`                        | `heic`      |    X      |
| `image/heif`                        | `heif`      |    X      |
| `video/mp4`                         | `mp4`       |           |
| `application/mp4`                   | `mp4`       |           |
| `audio/mp4`                         | `m4a`       |           |
| `video/quicktime`                   |  `mov`      |           |
| `application/x-c2pa-manifest-store` | `c2pa`      |           |

NOTE: Quicktime (`.mov`) format is not yet fully supported.

## Examples 

Here are some example uses of the tool that use files in the `attacks` and `sample` directories.  The examples operate on the sample image file `sample/C.jpg` which has attached Content Credentials and the `sample/test.json` manifest file.  

These examples create output in the `sample_out` directory.

### Inject into the author field using direct substitution

The following command is an example of using direct substituion. For a general explanation of using direct substitution, see [Using c2pa-attacks](./docs/usage.md#direct-substitution).

The following example reads attack strings one line at a time from the file `attacks/xss.attack` file and injects them into the `test.json` manifest file's author name field. The command saves its output in the `sample_out` directory. The `-f` flag forces overwrite of any existing files.

```shell
c2pa-attacks ./sample/C.jpg  \
-m ./sample/test.json \
-t author \
-a ./attacks/xss.attack \
-o ./sample_out/C_mod2.jpg -f 
```

This command outputs malicious files in the `sample_out` directory:
- `author_xss_0_C_mod2.jpg` has an associated manifest with the first line from `xss.attack` injected into the author name field.
- `author_xss_1_C_mod2.jpg`  has an associated manifest with the second line from `xss.attack` injected into the author name field.
- And so on.

### Inject into the author field using regex substitution

The following command is an example of using regex substituion. For a general explanation of using regex substitution, see [Using c2pa-attacks](./docs/usage.md#regex-substitution).

This example command reads attack strings one line at a time from the `xss.attack` file and injects them into the `author_name_regex.json` manifest file by replacing occurrences of the string "C2PA_ATTACK". The command saves its output in the `sample_out` directory. The `-f` flag forces overwrite of any existing files.

```shell
/c2pa-attacks ./sample/C.jpg \
-m ./sample/author_name_regex.json \
-a ./attacks/xss.attack \
-t regex \
-o ./sample_out/C_mod2.jpg -f 
```

This command outputs malicious files in the `sample_out` directory:

- `regex_xss_0_C_mod2.jpg` has an associated manifest with "C2PA_ATTACK" replaced with the first line from `xss.attack`.
- `regex_xss_0_C_mod2.jpg` has an associated manifest with "C2PA_ATTACK" replaced with the second line from `xss.attack`.
- And so on.

## Testing Certificate Authority fields

Security researchers can create self-signed certificate authorities and leaf certificates based on them. The C2PA project provides tools for generating certificates using OpenSSL in this repository: <https://github.com/c2pa-org/testing-private/tree/main/cert-generation>.

Within this project, the sample directory has a certificate with some unexpected values in common fields that can be used for signing. These certificates are based on a self-signed CA so any tools that validate against a trusted CA list won't accept them. However, you can use them to ensure that your certificate parsers can handle unexpected characters. They do not represent a complrehensive attack suite but it is a place to start.

To use the certificates with unexpected characters, use the `malicious_certificate.json` manifest file when running your tests. It will use the `malicious_certificate.pem` file and the `malicious_certificate.key` file to sign the C2PA images. For more complete testing, you can use the C2PA [testing-private](https://github.com/c2pa-org/testing-private/tree/main/cert-generation) repository mentioned above to create your own certificate chains. If you just need to test certificates with different algorithms, then there is a baseline suite located here: <https://github.com/contentauth/c2pa-rs/tree/main/sdk/tests/fixtures/certs>.


### Inspecting the created files

Install the [c2patool](https://github.com/contentauth/c2patool) so you can inspect individual files that this tool outputs. For more information, see [c2patool - C2PA command line tool](https://opensource.contentauthenticity.org/docs/c2patool/).

