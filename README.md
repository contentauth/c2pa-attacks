<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [C2PA Attacks](#c2pa-attacks)
  - [Overview](#overview)
  - [Why the build the tool?](#why-the-build-the-tool)
  - [Installation](#installation)
    - [Prerequisite](#prerequisite)
    - [Install c2pa-attacks](#install-c2pa-attacks)
    - [Updating](#updating)
  - [Testing locally in the Git directory](#testing-locally-in-the-git-directory)
  - [Example command lines](#example-command-lines)
    - [Inject into the author field via the command line](#inject-into-the-author-field-via-the-command-line)
    - [Inject into the author field using regex substitution in the JSON manifest](#inject-into-the-author-field-using-regex-substitution-in-the-json-manifest)
  - [Testing Certificate Authority fields](#testing-certificate-authority-fields)
    - [Inspecting the created files](#inspecting-the-created-files)
  - [Supported file formats](#supported-file-formats)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# C2PA Attacks

## Overview

This tool is used to generate C2PA images which can be used for security testing. The goal of this tool is to allow the security teams at C2PA partners to generate images for security testing their software for vulnerabilities such as cross-site scripting. The tool will ingest a file of attack strings, add the string into the designated manifest field, and produce a corresponding malicious C2PA image that can be uploaded to the website or provided to the software for testing. The tool does not automatically check to see if the attack was successful.

Each C2PA tool or service will have its own unique behavior and technology stack. Therefore, this tool is a framework for generating malicious images for testing in a manner that can be customized for specific targets. It is expected that the user of the tool will create customized attack files for their specific environment. The files provided with this tool are just examples for initial experimentation.

NOTE: This tool is a modification of the open-source C2PA [c2patool](https://github.com/contentauth/c2patool), but is not a replacement for it. The c2patool contains much more functionality and is a companion for this tool during analysis and testing.

This tool includes the foundation for a testing environment. Refer to the appendices for information on how to expand this tool's baseline to cover more file types, more injections, and other forms of code coverage.

## Why the build the tool?

The C2PA community should be empowered to security test their own software and this tool will help facilitate that testing earlier in the development cycle. In theory, the first step for processing any C2PA image is to validate the signature and reject any image that isn't from a trusted CA. That said, it is still good to test the parsers since some hackers will find ways to get unexpected data into C2PA-related fields. In addition, it is conceivable that a C2PA member may write a tool that parses C2PA data without validating the certificate. Therefore, it will be critical that these tools can safely handle unexpected input.

## Installation

_What can we say about OS support?  Mac only?_

### Prerequisite

Install [Rust](https://www.rust-lang.org/tools/install). 

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

The tool will display the version installed. Compare the version number displayed with the latest release version shown in the [repository releases page](https://github.com/contentauth/c2patool/releases). To update to the latest version, use the installation command shown above.

## Testing locally in the Git directory

If you just want to do local testing builds, then you can specify the make command followed by your corresponding OS platform. If you are using linux or the Windows Subsystem for Linux (WSL), then you will need development utilities such as `make` and `build-essential` already installed. To build c2pa-attacks, refer to the Makefile to identify the OS platform options for your environment:

```shell
rm -rf ./target/*
make build-release-{YOUR_OS_PLATFORM}-{YOUR_CPU}
./target/{YOUR_OS_PLATFORM}/release/c2pa-attacks
```

## Example command lines 

To get started without reading through all of this documentation, here are some example working command lines. The paragraph before each command explains how the tool interprets the command line. The files referenced in these examples are a part of this Git repository.

As a prerequisite, the tool assumes that you have certificates for signing the content. This repository includes a certificate and signing key in the sample directory. The associated `test.json` manifest in the sample directory references this certificate for doing initial tests of this tool. Therefore, these certificates are what will be implicitly used in the command lines below. However, these certificates may not to be recognized by your target application. You may need to generate your own certificates from an approved CA for your platform. The requirements for signing certificates are outlined in the C2PA [spec](https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_certificate_profile). Once you have your own certificates, then you can use those instead as described in the [Appendix](#appendix:-creating-and-using-an-x.509-certificate) of this document.

### Inject into the author field via the command line

```shell
c2pa-attacks ./sample/C.jpg  -m ./sample/test.json -t author -a ./attacks/xss.attack -o ./sample_out/C_mod2.jpg -f 
```
The above command line translates to the following steps:

1. Start with the baseline image: C.jpg
2. Add the manifest specified in test.json
3. Modify the manifest's author name by injecting strings from the file xss.attack
4. Output the signed results into the sample_out directory with filenames that end with C_mod2.jpg
5. Force overwrite any existing files.

The result of this command will be malicious files generated in the sample_out directory with filenames: *author_xss_0_C_mod2.jpg*, *author_xss_1_C_mod2.jpg*, *author_xss_2_C_mod2.jpg*, etc. The file *author_xss_0_C_mod2.jpg* will have the first line from xss.attack injected into the author's name. The file *author_xss_1_C_mod2.jpg* will have the second line from xss.attack injected into the author's name. 

### Inject into the author field using regex substitution in the JSON manifest

```shell
/c2pa-attacks ./sample/C.jpg  -m ./sample/author_name_regex.json -a ./attacks/xss.attack -t regex -o ./sample_out/C_mod2.jpg -f 
```
The above command line translates to:

1. Start with the baseline C.jpg image
2. Read the attack strings from xss.attack
3. Read the manifest specified in test.json
4. Replace any occurrences of the string "C2PA_ATTACK" in test.json with the appropriate attack string for that round.
5. Convert the new malicious JSON into a manifest
6. Output the signed results into the sample_out directory with filenames that end with C_mod2.jpg
7. Force overwrite any existing files.

The result of this command will be malicious files generated in the sample_out directory with filenames: `regex_xss_0_C_mod2.jpg`, `regex_xss_1_C_mod2.jpg`, `regex_xss_2_C_mod2.jpg`, and so on. Anywhere in `test.json` that had the string, "C2PA_ATTACK", will have been replaced with the corresponding attack string for that loop.

## Testing Certificate Authority fields

It is possible for security researchers to create self-signed certificate authorities and leaf certificates based on them. The C2PA project provides tools for generating certificates using OpenSSL in this repository: <https://github.com/c2pa-org/testing-private/tree/main/cert-generation>.

Within this project, the sample directory has a certificate with some unexpected values in common fields that can be used for signing. These certificates are based on a self-signed CA so they won't be accepted by any tools that are validating against a trusted CA list. However, they can be used to ensure that your certificate parsers can handle unexpected characters. They do not represent a complrehensive attack suite but it is a place to start.

To use the certificates with unexpected characters, use the *malicious_certificate.json* manifest file when running your tests. It will use the *malicious_certificate.pem* file and the *malicious_certificate.key* file to sign the C2PA images. For more complete testing, you can use the C2PA [testing-private](https://github.com/c2pa-org/testing-private/tree/main/cert-generation) repository mentioned above to create your own certificate chains. If you just need to test certificates with different algorithms, then there is a baseline suite located here: <https://github.com/contentauth/c2pa-rs/tree/main/sdk/tests/fixtures/certs>.


### Inspecting the created files

Install the [c2patool](https://github.com/contentauth/c2patool) so you can inspect individual files that are the output of this tool. For more information, see [c2patool - C2PA command line tool](https://opensource.contentauthenticity.org/docs/c2patool/).

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

