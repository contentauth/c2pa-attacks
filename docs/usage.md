# Using c2pa-attacks 

- [Command-line syntax](#command-line-syntax)
- [Supported target values](#supported-target-values)
  - [Direct substitution](#direct-substitution)
  - [Regex substitution](#regex-substitution)
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
| `--target` | `-t` | `<target>` | Specifies the target value for injection. One of: `title`, `author`, `claim_generator`, `person_identifier`, `vendor`, `label`, `instance_id`, `format`, or `regex`. See [Supported target values](#supported-target-values). |
| `--attack_file` | `-a` | `<attack_file>` | Specifies the file with the list of injections. See [Creating attack files](#creating-attack-files). |
| `--config` | `-c` | `<config>` | Specifies a manifest definition as a JSON string. See [Providing a manifest definition on the command line](#providing-a-manifest-definition-on-the-command-line). |
| `--manifest` | `-m` | `<manifest_file>` | Specifies a manifest file to add to an asset file. See [Adding a manifest to an asset file](#adding-a-manifest-to-an-asset-file).
| `--parent` | `-p` | `<parent_file>` | Specifies the path to the parent file. See [Specifying a parent file](#specifying-a-parent-file). |
| `--output` | `-o` | `<output_file>` | Specifies the path and title for the output files. See [Displaying manifest data](#adding-a-manifest-to-an-asset-file). |
| `--detailed` | `-d` | N/A | Display detailed C2PA-formatted manifest data. See [Detailed manifest report](#detailed-manifest-report). |
| `--force` | `-f` | N/A | Force overwriting of the output file. See [Forced overwrite](#forced-overwrite). |
| `--version` | `-V` | N/A | Display version information. |
| `--help` | `-h` | N/A | Display CLI help information. |

## Supported target values

The tool can inject malicious strings into manfiests before signing in two ways, depending on the argument of the `--target` option:
- If the argument is `regex`, then it uses [**regular expression substitution**](#regex-substitution) where it replaces the string "C2PA_ATTACK" anywhere it occurs in the manifest JSON file.
- If the argument is any other valid value, it uses [**direct substitution**](#direct-substitution) where it replaces the value of one specified field in the manifest JSON file.  

### Direct substitution

The simplest approach is to directly inject a value into a specified manifest field. This approach is supported only for some common fields because there are too many manifest fields to make them all available from a command line. More fields will be added as the tool matures. 

This approach is an easy way to start testing the most common fields without understanding JSON manifests.  The injections in this approach are done after the JSON file has been imported and turned into a manifest structure in memory. Therefore, you can inject any type of character using this method.

You can specify only one value as the argument for this option.

| Argument value | Description | Example value in `test.json` |
|----------------|-------------|------------------------------|
| `title` | The title field for the image. | "My Title" |
| `author` | The author name within the Creative Work assertion. | "Joe Bloggs" |
| `person_identifier` | With the Creative Work assertion, this refers to the Creative Work's URL identifier for that SchemaDotOrg Person entry. For further information, see [C2PA Technical Specification](https://c2pa.org/specifications/specifications/1.3/specs/C2PA_Specification.html#_use_of_schema_org). | N/A |
| `claim_generator` | The claim generator field in the manifest. | "TestApp" |
| `vendor` | Sets the vendor prefix to be used when generating manifest labels. For some strings, you will see an error `claim could not be converted to CBOR`. This just means that one of the attack strings couldn't be converted due to being incompatible. Attack strings that are compatible with CBOR will work and images will be generated. | N/AA |
| `label` | The label for the manifest assertion. For some strings, you will see an error `claim could not be converted to CBOR`. This just means that one of the attack strings couldn't be converted due to being incompatible. Attack strings that are compatible with CBOR will work and images will be generated. | "stds.schema-org.CreativeWork", "c2pa.actions", and "my.assertion". |
| `instance_id` | The XMP instance ID for the assertion. | N/A |
| `format` | Sets the format for the assertion's ingredient. | N/A |

### Regex substitution

If the target value is `regex`, then tool searches the manifest file for the string, "C2PA_ATTACK" and replaces all occurrences of it with the malicious string before embedding the assertion into the file.  The advantage of this approach is that you can inject malicous strings into any field of the manifest file including custom fields. However, for unit testing, you would likely only want one "C2PA_ATTACK" string per manifest file.

Since the tool injects malicious values into a JSON string, any trailing backslashes or quotes are automatically escaped to ensure the manifest is valid JSON. In addition, the [Serde serialization framework](https://serde.rs/) checks for control characters (0x00 - 0x32) and throws an error if it detects them; see [serde_json's escape logic](https://github.com/serde-rs/json/blob/master/src/read.rs#L787). Therefore, these types of character injections are not allowed in the regex workflow. A future release will add a feature to inject these characters just before signing the file.

## Creating attack files

The C2PA Attack Tool needs to know what values to use for the injection attacks. 
The tool uses plain text _attack files_ that it reads one line at a time.

The specific attack strings that will be successful depend on the target application and its technology stack.  For instance, if you are targeting a web application, then the attack strings might be cross-site scripting injections. If you are targeting a desktop application, then an attack string might be a really long string of 'a's in order to trigger a buffer overflow. 

The [`attacks` directory](../attacks/README.md) contains a few example attack strings to help get you started.  Use these as a starting point to create your own attack files appropriate for your particular situation. 

## Providing a manifest definition on the command line

To provide the manifest definition in a command line argument instead of a file, use the `--config` / `-c` option.

For example, the following command adds a custom assertion called "org.contentauth.test".

```shell
c2pa-attacks sample/image.json \
-c '{"assertions": [{"label": "org.contentauth.test", "data": {"my_key": "C2PA_ATTACK"}}]}' \
-t regex \
-a attacks/xss.attack
```

## Adding a manifest to an asset file

To add manifest data to a file, provide the path to the asset file to be signed and use the `--manifest` / `-m` option with a manifest JSON file as the option argument. Then, use the `--output` / `-o` option to specify the desired location and name suffix for the output files.
If you do not use the `--output` / `-o` option, then the tool will not generate any output.
The tool will put all of the manipulated file in the same folder as the image specified in the output flag. 

CAUTION: If the output file is the same as the source file, the tool will overwrite the source file. 

For example, in the following example line, the tool puts all of the generated files in the `sample_out` directory and will create it if it does not exist. 

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


