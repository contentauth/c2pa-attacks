# C2PA Attacks

## Overview

This tool is used to generate C2PA images which can be used for security testing. The goal of this tool is to allow the security teams at C2PA partners to generate images for security testing their software for vulnerabilities such as cross-site scripting. The tool will ingest a file of attack strings, add the string into the designated manifest field, and produce a corresponding malicious C2PA image that can be uploaded to the website or provided to the software for testing. The tool does not automatically check to see if the attack was successful.

Each C2PA tool or service will have its own unique behavior and technology stack. Therefore, this tool is a framework for generating malicious images for testing in a manner that can be customized for specific targets. It is expected that the user of the tool will create customized attack files for their specific environment. The files provided with this tool are just examples for initial experimentation.

Please note: While this tool is a modification of the open-source C2PA [c2patool](https://github.com/contentauth/c2patool), it is not a replacement for that tool. The c2patool contains much more functionality and the c2patool would be a companion for this tool during analysis and testing.

This tool includes the foundation for a testing environment. Refer to the appendices for information on how to expand this tool's baseline to cover more file types, more injections, and other forms of code coverage.

## Why the build the tool?

The C2PA community should be empowered to security test their own software and this tool will help facilitate that testing earlier in the development cycle. In theory, the first step for processing any C2PA image is to validate the signature and reject any image that isn't from a trusted CA. That said, it is still good to test the parsers since some hackers will find ways to get unexpected data into C2PA-related fields. In addition, it is conceivable that a C2PA member may write a tool that parses C2PA data without validating the certificate. Therefore, it will be critical that these tools can safely handle unexpected input.

## Example command lines 

For those that want to jump in without fulling reading this document, here are some example working command lines. The paragraph before each command explains how the tool interprets the command line. The files referenced in these examples are a part of this git repository.

As a pre-requisite, the tool assumes that you have certificates for signing the content. This repository includes a certificate and signing key in the sample directory. The associated test.json manifests in the sample directory references this certificate for doing initial tests of this tool. Therefore, these certificates are what will be implicitly used in the command lines below. However, these certificates may not to be recognized by your target application. You may need to generate your own certificates that are from an approved CA for your platform. The requirements for signing certificates are outlined in the C2PA [spec](https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_certificate_profile). Once you have your own certificates, then you can use those instead as described in the [Appendix](#appendix:-creating-and-using-an-x.509-certificate) of this document.

### Example command #1: Injecting into the Author field via the command line

```shell
/c2pa-attacks ./sample/C.jpg  -m ./sample/test.json -t author -a ./attacks/xss.attack -o ./sample_out/C_mod2.jpg -f 
```
The above command line translates to the following steps:

1. Start with the baseline image: C.jpg
2. Add the manifest specified in test.json
3. Modify the manifest's author name by injecting strings from the file xss.attack
4. Output the signed results into the sample_out directory with filenames that end with C_mod2.jpg
5. Force overwrite any existing files.

The result of this command will be malicious files generated in the sample_out directory with filenames: *author_xss_0_C_mod2.jpg*, *author_xss_1_C_mod2.jpg*, *author_xss_2_C_mod2.jpg*, etc. The file *author_xss_0_C_mod2.jpg* will have the first line from xss.attack injected into the author's name. The file *author_xss_1_C_mod2.jpg* will have the second line from xss.attack injected into the author's name. 

### Example command #2 -- Injecting into the author field using regex substitution in the JSON manifest

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

The result of this command will be malicious files generated in the sample_out directory with filenames: *regex_xss_0_C_mod2.jpg*, *regex_xss_1_C_mod2.jpg*, *regex_xss_2_C_mod2.jpg*, etc. Anywhere in test.json that had the string, "C2PA_ATTACK", will have been replaced with the corresponding attack string for that loop.

## Testing Certificate Authority fields

It is possible for security researchers to create self-signed certificate authorities and leaf certificates based on those self-signed CAs. The C2PA project provides tools for generating certificates using openssl in this repository: <https://github.com/c2pa-org/testing-private/tree/main/cert-generation>.

Within this project, the sample directory has a certificate with some unexpected values in common fields that can be used for signing. These certificates are based on a self-signed CA so they won't be accepted by any tools that are validating against a trusted CA list. However, they can be used to ensure that your certificate parsers can handle unexpected characters. They do not represent a complrehensive attack suite but it is a place to start.

To use the certificates with unexpected characters, use the *malicious_certificate.json* manifest file when running your tests. It will use the *malicious_certificate.pem* file and the *malicious_certificate.key* file to sign the C2PA images. For more complete testing, you can use the C2PA [testing-private](https://github.com/c2pa-org/testing-private/tree/main/cert-generation) repository mentioned above to create your own certificate chains. If you just need to test certificates with different algorithms, then there is a baseline suite located here: <https://github.com/contentauth/c2pa-rs/tree/main/sdk/tests/fixtures/certs>.

## Full installation

PREREQUISITE: Install [Rust](https://www.rust-lang.org/tools/install). 

Enter this command to install or update the tool:

```shell
cargo install c2pa-attacks
```

## Testing locally in the git directory

If you just want to do local testing builds, then you can specify the make command followed by your corresponding OS platform. If you are using linux or the Windows Subsystem for Linux (WSL), then you will need development utilities such as `make` and `build-essential` already installed. To build c2pa-attacks, refer to the Makefile to identify the OS platform options for your environment:

```shell
rm -rf ./target/*
make build-release-{YOUR_OS_PLATFORM}-{YOUR_CPU}
./target/{YOUR_OS_PLATFORM}/release/c2pa-attacks
```

### Updating

To ensure you have the latest version, enter this command:

```
c2pa-attacks -V 
```

The tool will display the version installed. Compare the version number displayed with the latest release version shown in the [repository releases page](https://github.com/contentauth/c2patool/releases). To update to the latest version, use the installation command shown above.

### Inspecting the created files

It is highly recommended that you also install the [c2patool](https://github.com/contentauth/c2patool). This will allow you to inspect individual files that are the output of this tool. Please see the c2patool's documentation for more information.

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

## Usage

The tool's command-line syntax is:

```
c2pa-attacks [OPTIONS] [path]
```

Where `<path>`  is the path to the asset to embed a manifest into.

The following table describes the command-line options.

| CLI&nbsp;option&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Short version | Argument | Description |
|-----|----|----|----|
| `--target` | `-t` | `<target>` | Specifies the target value for injection. See [Supported target values](#supported-target-values). |
| `--attack_file` | `-a` | `<attack_file>` | Specifies the file with the list of injections. See [Creating attack files](#creating-attack-files). |
| `--config` | `-c` | `<config>` | Specifies a manifest definition as a JSON string. See [Providing a manifest definition on the command line](#providing-a-manifest-definition-on-the-command-line). |
| `--manifest` | `-m` | `<manifest_file>` | Specifies a manifest file to add to an asset file. See [Adding a manifest to an asset file](#adding-a-manifest-to-an-asset-file).
| `--parent` | `-p` | `<parent_file>` | Specifies the path to the parent file. See [Specifying a parent file](#specifying-a-parent-file). |
| `--output` | `-o` | `<output_file>` | Specifies the path and title for the output files. See [Displaying manifest data](#adding-a-manifest-to-an-asset-file). |
| `--detailed` | `-d` | N/A | Display detailed C2PA-formatted manifest data. See [Detailed manifest report](#detailed-manifest-report). |
| `--force` | `-f` | N/A | Force overwriting of the output file. See [Forced overwrite](#forced-overwrite). |
| `--version` | `-V` | N/A | Display version information. |
| `--help` | `-h` | N/A | Display CLI help information. |

### Supported target values

The C2PA attack tool has two general methods for injecting malicious strings. These options are all mutually exclusive and cannot be used together. The currently supported values are: "title", "author", "claim_generator", "person_identifier", "vendor", "label", "instance_id", "format", and "regex". 

The meaning of these flags are as follows:

- *title*: The Title field for the image. In the test.json file, this would be the "My Title" field.
- *author*: The Author Name within the Creative Work assertion. In the test.json file, this would be the field with the name "Joe Bloggs".
- *person_identifier*: With the Creative Work assertion, this refers to the Creative Work's URL identifier for that SchemaDotOrg Person entry. For further information, see: <https://c2pa.org/specifications/specifications/1.3/specs/C2PA_Specification.html#_use_of_schema_org>
- *claim_generator*: The Claim Generator field in the manifest. In the test.json file, this would correspond with the "TestApp" value for "claim_generator".
- *vendor*: Sets the vendor prefix to be used when generating manifest labels. For some strings, you will see an error `claim could not be converted to CBOR`. This just means that one of the attack strings couldn't be converted due to being incompatible. Attack strings that are compatible with CBOR will work and images will be generated.
- *label*: Sets the label for this manifest assertion. For some strings, you will see an error `claim could not be converted to CBOR`. This just means that one of the attack strings couldn't be converted due to being incompatible. Attack strings that are compatible with CBOR will work and images will be generated.
- *instance_id*: Sets the XMP instance ID for the assertion.
- *format*: Sets the format for the assertion's ingredient.
- *regex*: This indicates that the provided manifest should be searched for the "C2PA_ATTACK" field. This approach allows greater freedom in specifying the specific field that should be manipulated.

#### Method 1: Direct substitutions

The simplest approach is to directly inject into the compiled manifest before signing. This approach is only supported for a few common fields because there are too many possible manifest fields to make them all available from a command line. The advantage of this approach is that it is an easy way to start testing the most common fields without understanding JSON manifests. The currently available options are the title, author, and claim generator. More fields will be added as the tool matures. The injections in this approach are done after the JSON file has been imported and turned into a manifest structure in memory. Therefore, any type of character can be injected via this method.

#### Method 2: Regex

If the target value is "regex", then this instructs the attack tool to search the file specified by the manifest parameter for the string, "C2PA_ATTACK". When building a malicious image, the C2PA attack tool will replace all occurrences of the string "C2PA_ATTACK" with the malicious string before embedding the assertion into the file. Although, you would likely only want one "C2PA_ATTACK" string per manifest file for the sake of unit testing. The advantage of this approach is that it allows you to inject malicous strings into any parameter of the manifest file including custom parameters.

Since the tool is injecting malicious values into a JSON string, any trailing backslashes or quotes are automatically escaped in order to ensure the manifest is valid JSON. In addition, the serde serialization framework checks for control characters (0x00 - 0x32) and throws an error if detected. (See: [serde_json's escape logic](https://github.com/serde-rs/json/blob/master/src/read.rs#L787) ) Therefore, these types of character injections are not allowed in the regex workflow. A future release will add a feature for injecting these characters just before signing the file.

### Creating attack files

The C2PA Attack tool needs to know what values to use for the injection attacks. Whether a given injection value is successful will depend on the type of application and technology stack that is used. Therefore, the open source project includes a few generic attack strings so that people can play with the tool. However, it is expected that security researchers will create their own attack files that are appropriate for the given situation. For instance, if you are targeting a web application, then your attack strings might be cross-site scripting injections. If you are targeting a desktop application, then your injection strings might be a really long string of 'a's in order to trigger a buffer overflow. The [README.md](./attacks/README.md) file in the attacks directory provides some more specific suggestions on how to build and select robust attack files for your application. The attack files are plain text files that are read one line at a time.

### Providing a manifest definition on the command line

To provide the [manifest definition](#manifest-definition-file) in a command line argument instead of a file, use the `--config` / `-c` option.

For example, the following command adds a custom assertion called "org.contentauth.test".

```shell
c2pa-attacks sample/image.json -c '{"assertions": [{"label": "org.contentauth.test", "data": {"my_key": "C2PA_ATTACK"}}]}' -t regex -a attacks/xss.attack
```

### Adding a manifest to an asset file

To add C2PA manifest data to a file, provide the path to the asset file to be signed and use the `--manifest` / `-m` option with a manifest JSON file as the option argument. Then, use the `--output` / `-o` option to specify the desired location and name suffix for the output files. The output option is required to generate manipulated files. All of the manipulated files will be put in the same folder as the image specified in the output flag. For example, assume the following command line:

```shell
c2pa-attacks sample/image.jpg -m sample/test.json -o sample_out/signed_image.jpg -t title -a attacks/xss.attack
```

In the example above, all of the generated files will be placed in the `sample_out` directory. If the `sample_out` directory does not exist, then it will be created. The first generated file would be named, `sample_out/title_xss_0_signed_image.jpg`, as previously described. 

CAUTION: If the output file is the same as the source file, the tool will overwrite the source file. 

If you do not use the `--output` / `-o` option, then the tool will not generate any output.

#### IMPORTANT NOTE

Since the C2PA Attack tool produces multiple output files per run, the filename specified in the output flag will be prefixed with the target type and the line number from the attack file that was injected. Therefore, the above example would produce the files: *title_0_signed_image.jpg*, *title_1_signed_image.jpg*, *title_2_signed_image.jpg*, etc.

#### Specifying a parent file

A parent file represents the state of the image before the current edits were made. 

Specify a parent file as the argument to the `--parent` / `-p` option; for example:

```shell
c2pa-attacks sample/image.jpg -m sample/test.json -p sample/c.jpg -o sample_out/signed_image.jpg -t title -a attacks/xss.attack
```

You can also specify a parent file in the manifest definition.

### Detailed manifest report

To display a detailed report describing the internal C2PA format of manifests contained in the asset, use the `-d` option. This only works when `-v` is also specified.  The tool displays the detailed report to standard output (stdout). 

#### Forced overwrite

The tool will return an error if the output file already exists. Use the `--force` / `-f` option to force overwriting the output file. For example:

```shell
c2pa-attacks sample/image.jpg -m sample/test.json -f -o sample_out/signed_image.jpg
```

## Appendix

### C2PA references

The "c2patool" is a good complimentary tool for inspecting the files created by this tool: <https://github.com/contentauth/c2patool>

This document contains technical specifications for C2PA standard assertions including JSON samples: <https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_c2pa_standard_assertions>

### Injection string references

OWASP Overview of cross-site scripting with links on how to test on the different forms of cross-site scripting: <https://owasp.org/www-community/attacks/xss/>

OWASP Testing Guide section on SQL Injection: <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection>

PayloadBox GitHub Repo has a collection of injection strings: <https://github.com/payloadbox>

### Additional baseline test case files

If you want more sample file types beyond JPEGs for testing, the C2PA maintains a list of sample files here: <https://github.com/c2pa-org/public-testfiles>

### Creating and using an X.509 certificate

If you want to create your own certificate authority, then there are openssl tools available here: <https://github.com/c2pa-org/testing-private/blob/main/cert-generation/genca.sh>

Rather than generating your own certs, you can also test creating your own manifests using the pre-built certificates in the [sample folder](https://github.com/contentauth/c2patool/tree/main/sample). To use your own generated certificates, specify the path to the cert files in the following manifest fields:

- `private_key`
- `sign_cert`

If you are using a signing algorithm other than the default `es256`, specify it in the manifest definition field `alg` with one of the following values:

- `ps256`
- `ps384`
- `ps512`
- `es256`
- `es384`
- `es512`
- `ed25519`

The specified algorithm must be compatible with the values of `private_key` and `sign_cert`.

You can put the values of the key and cert chain in two environment variables: `C2PA_PRIVATE_KEY` (for the private key) and `C2PA_SIGN_CERT` (for the public certificates). For example, to sign with ES256 signatures using the content of a private key file and certificate file:

```shell
set C2PA_PRIVATE_KEY=$(cat my_es256_private_key)
set C2PA_SIGN_CERT=$(cat my_es256_certs)
```

Both the `private_key` and `sign_cert` must be in PEM format. The `sign_cert` must contain a PEM certificate chain starting with the end-entity certificate used to sign the claim ending with the intermediate certificate before the root CA certificate. See the [sample folder](https://github.com/contentauth/c2patool/tree/main/sample) for example certificates.
