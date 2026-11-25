# Using c2pa-attacks 

- [Command-line syntax](#command-line-syntax)
- [Supported target values](#supported-target-values)
  - [Direct substitution](#direct-substitution)
  - [Regex substitution](#regex-substitution)
- [CAWG metadata and legacy testing](#cawg-metadata-and-legacy-testing)
- [Creating attack files](#creating-attack-files)
- [Providing a manifest definition on the command line](#providing-a-manifest-definition-on-the-command-line)
- [Adding a manifest to an asset file](#adding-a-manifest-to-an-asset-file)
  - [Specifying a parent file](#specifying-a-parent-file)
- [Detailed manifest report](#detailed-manifest-report)
- [Forced overwrite](#forced-overwrite)

## Command-line syntax

The command-line syntax for `c2pa-attacks` is:

```
c2pa-attacks [OPTIONS] [path]
```

Where `<path>`  is the path to the asset to embed a manifest into.

The following table describes the command-line options.

| CLI&nbsp;option&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Short version | Argument | Description |
|-----|----|----|----|
| `--target` | `-t` | `<target>` | One of: `title`, `cawg_author`, `cawg_person_identifier`, `author`, `claim_generator`, `person_identifier`, `vendor`, `label`, `instance_id`, `format`, or `regex`. Prefer `regex` templates for broader CAWG coverage. |
| `--attack_file` | `-a` | `<attack_file>` | Specifies the file with the list of injections. See [Creating attack files](#creating-attack-files). |
| `--config` | `-c` | `<config>` | Manifest definition as a JSON string; mutually exclusive with `--manifest`. |
| `--manifest` | `-m` | `<manifest_file>` | Manifest definition file; provide exactly one of this or `--config`. |
| `--parent` | `-p` | `<parent_file>` | Specifies the path to the parent file. See [Specifying a parent file](#specifying-a-parent-file). |
| `--no_signing_verify` | None | N/A |  Do not validate the signature after signing an asset, which speeds up signing. See [Speeding up signing](#speeding-up-signing) |
| `--output` | `-o` | `<output_file>` | Specifies the path and title for the output files. See [Displaying manifest data](#adding-a-manifest-to-an-asset-file). |
| `--detailed` | `-d` | N/A | Display detailed C2PA-formatted manifest data. See [Detailed manifest report](#detailed-manifest-report). |
| `--trust` | N/A | N/A | Set additional trust validation parameters. See [Configuring trust support](#configuring-trust-support). |
| `--force` | `-f` | N/A | Force overwriting of the output file. See [Forced overwrite](#forced-overwrite). |
| `--version` | `-V` | N/A | Display version information. |
| `--help` | `-h` | N/A | Display CLI help information. |

## Supported target values

The tool can inject malicious strings into manfiests before signing in two ways, depending on the argument of the `--target` option:
- If the argument is `regex`, then it uses [**regular expression substitution**](#regex-substitution) where it replaces the string "C2PA_ATTACK" anywhere it occurs in the manifest JSON file.
- If the argument is any other valid value, it uses [**direct substitution**](#direct-substitution) where it replaces the value of one specified field in the manifest JSON file.  

### Direct substitution

This was the simplest approach when the c2pa-attacks tool was first created. Although, as the C2PA specification and the Rust SDK matured, this approach became less relevant. In most cases, the Regex subsitution is the better approach. Although, several of these options are still usable.

This approach is an easy way to start testing common fields. CAWG presets mutate the JSON definition before SDK import; the legacy presets and claim-field mutations use the Builder before signing. As noted below, some options are no longer relevant due to changes in the SDK.

This command line option only accepts one value as an argument.

| Argument value | Description | Example value in `test.json` |
|----------------|-------------|------------------------------|
| `title` | The title field for the image. | "My Title" |
| `cawg_author` | Sets `schema:author[0].schema:name` in a JSON `cawg.metadata` assertion. | "Content Creator" |
| `cawg_person_identifier` | Sets `schema:author[0].schema:identifier` in `cawg.metadata`; does not enforce URL syntax or alter `@id`. | "https://example.com/creator" |
| `author` | The author name within the Creative Work assertion. NOTE: The CreativeWork assertion was dropped from version 2.0 of the C2PA specification, but it will still be displayed by implementations that are backwards compatible with the 1.0 version. | "Content Creator" |
| `person_identifier` | With the Creative Work assertion, this refers to the Creative Work's URL identifier for that SchemaDotOrg Person entry. For further information, see [C2PA Technical Specification](https://c2pa.org/specifications/specifications/1.4/specs/C2PA_Specification.html#_use_of_schema_org). NOTE: The CreativeWork assertion was dropped from version 2.0 of the C2PA specification but it will still be displayed by implementations that are backwards compatible with the 1.0 version. | N/A |
| `claim_generator` | The claim generator field in the manifest. | "TestApp" |
| `vendor` | Sets the vendor prefix to be used when generating manifest labels. For some strings, you will see an error that the `claim could not be converted to CBOR`. This means that one of the characters in the attack string is incompatible with CBOR. Attack strings that are compatible with CBOR will work and images will be generated. Note that this value will get a urn:uuid appended to it by the SDK per the specification. | N/A |
| `label` | The label for the claim. This value is expected to be a [GUID](https://github.com/contentauth/c2pa-rs/blob/c2pa-v0.48.2/sdk/src/claim.rs#L429) and it is validated according to these [validation rules](https://docs.rs/uuid/latest/src/uuid/parser.rs.html#98-100). Injecting any malicious string that isn't in the GUID format enforced by UUID parser will throw an error. However, this might be useful if you have a need to set specific UUIDs as part of the attack. This represents the primary label for the claim and it does not affect other label values. | N/A |
| `instance_id` | The instance ID for the claim. NOTE: This is currently no longer supported because the latest version of the [SDK overrides](https://github.com/contentauth/c2pa-rs/blob/c2pa-v0.48.2/sdk/src/builder.rs#L993) any set value before signing. | N/A |
| `format` | Sets the format for the assertion's ingredient. NOTE: This is currently no longer supported because the current version of the SDK [determines the format](https://github.com/contentauth/c2pa-rs/blob/c2pa-v0.48.2/sdk/src/builder.rs#L1125) by looking at the file extension of the file to be signed. If you want the format to be different from the actual file, then change the file extension before signing to a supported file type. See: https://github.com/contentauth/c2pa-rs/blob/c2pa-v0.48.2/sdk/src/utils/mime.rs | N/A |

### Regex substitution

If the target value is `regex`, then tool searches the JSON manifest file for the string, "C2PA_ATTACK" and replaces all occurrences of it with the malicious string before embedding the assertion into the file.  The advantage of this approach is that you can inject malicous strings into any field of the manifest file including custom fields. However, for unit testing, you would likely only want one "C2PA_ATTACK" string per manifest file.

Payloads are JSON-string-escaped using Serde, including quotes, backslashes, and control characters. Dollar signs are literal, not replacement-group references. Place markers inside JSON strings (including string keys); this mode does not insert raw JSON objects or code. Every occurrence is replaced, so use one marker to isolate a field. Each attack-file line is a separate payload; line separators are not part of it.

## CAWG metadata and legacy testing

SDK 0.92.2 no longer exports the legacy `CREATIVE_WORK` label constant. The tool retains `author` and `person_identifier` as explicit legacy CreativeWork testing modes and prints a warning; existing invocations are not silently converted. Schema.org assertions were already deprecated in [C2PA 1.4](https://spec.c2pa.org/specifications/specifications/1.4/specs/C2PA_Specification.html#_use_of_schema_org).

For current metadata tests, use [CAWG Metadata 1.1](https://cawg.io/metadata/1.1/#_assertion_definition): the assertion label is `cawg.metadata`, its content is JSON, and its `@context` maps schema prefixes to namespaces. This is **metadata testing, not signed CAWG Identity testing**; an author name or identifier does not prove control over an identity.

### Template-first configuration

As in c2patool, the ordinary SDK manifest definition configures the job: assertion data, schemas, ingredients, claim version, and development signing configuration. Use `-m/--manifest` for a file or `-c/--config` for inline JSON, never both. Resource paths in files resolve relative to the manifest file; inline resource paths resolve relative to the current directory. The tool adds attack substitution and one output per payload to the SDK Builder/signing workflow, not a separate CAWG configuration format.

```shell
c2pa-attacks sample/image.jpg \
  -m sample/cawg_author_regex.json -t regex \
  -a attacks/xss.attack -o sample_out/cawg.jpg
```

Use `sample/cawg_person_identifier_regex.json` to target identifiers. To target another metadata field, edit the template rather than add CLI flags. For example, this assertion tests Dublin Core creators with the same `-t regex` mode:

```json
{
  "label": "cawg.metadata",
  "kind": "Json",
  "data": {
    "@context": { "dc": "http://purl.org/dc/elements/1.1/" },
    "dc:creator": ["C2PA_ATTACK"]
  }
}
```

Include it in a normal manifest definition with the appropriate creation/opening actions and signing configuration. This requires no Dublin Core preset. Other CAWG assertions, such as training/mining, can be supplied through compatible definitions; template flexibility alone does not supply the credential/signature workflow required for CAWG Identity.

### Two convenience presets

```shell
c2pa-attacks sample/image.jpg \
  -m sample/cawg_metadata.json --target cawg_author \
  -a attacks/xss.attack -o sample_out/cawg.jpg
```

Replace the target with `cawg_person_identifier` for identifier tests. These presets use `@context: {"schema": "https://schema.org/"}` and the first `schema:Person` in `schema:author`. If no CAWG metadata assertion exists, one is added; absent author/person data is created. Existing unrelated assertions, namespaces, properties, later authors, and claim-version settings are preserved. The identifier preset supplies `"Malicious User"` only if the name is missing.

Multiple CAWG metadata assertions, unsupported assertion versions, conflicting `schema` mappings, or incompatible first-author shapes produce an error suggesting a tailored regex template. The presets do not convert alternate JSON-LD schemas or layouts. CAWG does not mandate these particular Schema.org fields.

Legacy regression testing remains explicit:

```shell
c2pa-attacks sample/image.jpg \
  -m sample/test.json -t author \
  -a attacks/xss.attack -o sample_out/legacy.jpg
```

The legacy `person_identifier` target continues to inject into `identifier`, `@id`, and `creator`. New CAWG identifier presets target only `schema:identifier`; use templates for alternate locations. Output filename prefixes distinguish `cawg_author`, `cawg_person_identifier`, and legacy targets. If any payload fails, the batch continues but exits unsuccessfully, reporting the failures.

## Creating attack files

The C2PA Attack Tool needs to know what values to use for the injection attacks. 
The tool uses plain text _attack files_ that it reads one line at a time.

The specific attack strings that will be successful depend on the target application and its technology stack.  For instance, if you are targeting a web application, then the attack strings might be cross-site scripting injections. If you are targeting a desktop application, then an attack string might be a really long string of 'a's in order to trigger a buffer overflow. 

The [`attacks` directory](../attacks/README.md) contains a few example attack strings to help get you started.  Use these as a starting point to create your own attack files appropriate for your particular situation. 

## Providing a manifest definition on the command line

To provide the manifest definition in a command line argument instead of a file, use the `--config` / `-c` option.

For example, the following command adds a custom assertion called "org.contentauth.test".

```shell
c2pa-attacks sample/image.jpg \
-c '{"claim_version":2,"assertions":[{"label":"c2pa.actions.v2","data":{"actions":[{"action":"c2pa.created","digitalSourceType":"http://cv.iptc.org/newscodes/digitalsourcetype/computationalCapture"}]}},{"label":"org.contentauth.test","data":{"my_key":"C2PA_ATTACK"}}]}' \
-t regex \
-a attacks/xss.attack \
-o sample_out/custom.jpg
```

## Adding a manifest to an asset file

To add manifest data to a file, provide the path to the asset file to be signed and use the `--manifest` / `-m` option with a manifest JSON file as the option argument. The sample directory contains examples for both version 1 (`test.json`) and version 2 (`test_claim_v2.json`) claim manifests. Next, use the `--output` / `-o` option to specify the desired location and name suffix for the output files.
The `-o` option is required.
The tool will put all of the manipulated file in the same folder as the image specified in the output flag. 

CAUTION: If the output file is the same as the source file, the tool will overwrite the source file. 

For example, in the following example line, the tool puts all of the generated files in the `sample_out` directory and will create it if it does not exist. This command line is using the C2PA version 1 claim manifest example file. For a version 2 claim manifest, use `test_claim_v2.json` instead.

```shell
c2pa-attacks sample/image.jpg \
-m sample/test.json \
-o sample_out/signed_image.jpg \
-t title \
-a attacks/xss.attack
```

**IMPORTANT NOTE**: Since the tool produces multiple output files per run, it prefixes the filename specified in the output flag with the target type and (zero-based) line number from the attack file injected. Therefore, the above example would produce output files `title_xss_0_signed_image.jpg`, `title_xss_1_signed_image.jpg`, `title_xss_2_signed_image.jpg`, and so on.

### Specifying a parent file

A parent file represents the state of the image before the current edits were made. 

Specify a parent file as the argument to the `--parent` / `-p` option; for example:

```shell
c2pa-attacks sample/image.jpg \
-m sample/test.json \
-p sample/c.jpg \
-o sample_out/signed_image.jpg \
-t title \
-a attacks/xss.attack
```

You can also specify a parent file in the manifest definition.

## Detailed manifest report

To display a detailed report describing the internal C2PA format of manifests contained in the asset, use the `-d` option. This only works when `-v` is also specified.  The tool displays the detailed report to standard output (stdout). 

## Forced overwrite

The tool will return an error if the output file already exists. Use the `--force` / `-f` option to force overwriting the output file. For example:

```shell
c2pa-attacks sample/image.jpg \
-m sample/test.json \
-f -o sample_out/signed_image.jpg
```

## Speeding up signing

By default, `c2patool` validates the signature immediately after signing a manifest. To disable this and speed up the validation process, use the `--no_signing_verify` option.

## Configuring trust support

SDK 0.92 removes the old top-level `trust.trust_anchors` and `trust.user_anchors` fields. The tool's existing trust options and sidecar files now populate SDK `trust.anchors` entries of kind `manifest`, preserving other configured entries and enabling trust verification. Metadata testing does not grant trust to CAWG Identity credentials.

When supplying SDK settings directly, use the current format (PEM values omitted below):

```json
{
  "trust": {
    "anchors": [
      {
        "trust_kind": "manifest",
        "trust_anchors": "<PEM trust anchors>",
        "allowed_list": "<explicitly trusted signing certificates in PEM>"
      }
    ]
  },
  "verify": { "verify_trust": true }
}
```

For local sample tests, explicitly allow only the existing development fixture certificate using the `trust --allowed_list sample/es256_certs.pem` options. This is test-local trust, not a publicly trusted production credential, and does not disable signature verification.

Enable trust support by using the `trust` subcommand, as follows:

```
c2patool [path] trust [OPTIONS]
```

When the `trust` subcommand is supplied, should c2patool encounter a problem with validating any of the claims in the asset, its JSON output will contain a `validation_status` field whose value is an array of objects, each describing a validation problem.

### Additional options

Several additional CLI options are available with the `trust` sub-command to specify the location of files containing the trust anchors list or known certificate list, as described in the following table. You can also use environment variables to specify these values.

<div class="trust-table" markdown="1">

| Option | Environment variable | Description |
| ------ | -------------------- | ----------- | 
| `--trust_anchors` | `C2PATOOL_TRUST_ANCHORS` | URL or relative path to a file containing a list of trust anchors (in PEM format) used to validate the manifest certificate chain. To be valid, the manifest certificate chain must lead to a certificate on the trust list. All certificates in the trust anchor list must have the [Basic Constraints extension](https://docs.digicert.com/en/iot-trust-manager/certificate-templates/create-json-formatted-certificate-templates/extensions/basic-constraints.html) and the CA attribute of this extension must be `True`.  |
| `--allowed_list` | `C2PATOOL_ALLOWED_LIST` | URL or relative path to a file containing a list of end-entity certificates (in PEM format) to trust. These certificates are used to sign the manifest. Supersedes the `trust_anchors` setting. The list must NOT contain certificates with the [Basic Constraints extension](https://docs.digicert.com/en/iot-trust-manager/certificate-templates/create-json-formatted-certificate-templates/extensions/basic-constraints.html) with the CA attribute `True`. |
| `--trust_config` | `C2PATOOL_TRUST_CONFIG` | URL or relative path to a file containing the allowed set of custom certificate extended key usages (EKUs). Each entry in the list is an object identifiers in [OID dot notation](http://www.oid-info.com/#oid) format.  |
