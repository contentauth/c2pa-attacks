# Using c2pa-attacks 

- [Command-line syntax](#command-line-syntax)
- [Supported target values](#supported-target-values)
  - [Method 1: Direct substitutions](#method-1-direct-substitutions)
  - [Method 2: Regex](#method-2-regex)
- [Creating attack files](#creating-attack-files)
- [Providing a manifest definition on the command line](#providing-a-manifest-definition-on-the-command-line)
- [Adding a manifest to an asset file](#adding-a-manifest-to-an-asset-file)
  - [IMPORTANT NOTE](#important-note)
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

## Supported target values

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

### Method 1: Direct substitutions

The simplest approach is to directly inject into the compiled manifest before signing. This approach is only supported for a few common fields because there are too many possible manifest fields to make them all available from a command line. The advantage of this approach is that it is an easy way to start testing the most common fields without understanding JSON manifests. The currently available options are the title, author, and claim generator. More fields will be added as the tool matures. The injections in this approach are done after the JSON file has been imported and turned into a manifest structure in memory. Therefore, any type of character can be injected via this method.

### Method 2: Regex

If the target value is "regex", then this instructs the attack tool to search the file specified by the manifest parameter for the string, "C2PA_ATTACK". When building a malicious image, the C2PA attack tool will replace all occurrences of the string "C2PA_ATTACK" with the malicious string before embedding the assertion into the file. Although, you would likely only want one "C2PA_ATTACK" string per manifest file for the sake of unit testing. The advantage of this approach is that it allows you to inject malicous strings into any parameter of the manifest file including custom parameters.

Since the tool is injecting malicious values into a JSON string, any trailing backslashes or quotes are automatically escaped in order to ensure the manifest is valid JSON. In addition, the serde serialization framework checks for control characters (0x00 - 0x32) and throws an error if detected. (See: [serde_json's escape logic](https://github.com/serde-rs/json/blob/master/src/read.rs#L787) ) Therefore, these types of character injections are not allowed in the regex workflow. A future release will add a feature for injecting these characters just before signing the file.

## Creating attack files

The C2PA Attack tool needs to know what values to use for the injection attacks. Whether a given injection value is successful will depend on the type of application and technology stack that is used. Therefore, the open source project includes a few generic attack strings so that people can play with the tool. However, it is expected that security researchers will create their own attack files that are appropriate for the given situation. For instance, if you are targeting a web application, then your attack strings might be cross-site scripting injections. If you are targeting a desktop application, then your injection strings might be a really long string of 'a's in order to trigger a buffer overflow. The [README.md](./attacks/README.md) file in the attacks directory provides some more specific suggestions on how to build and select robust attack files for your application. The attack files are plain text files that are read one line at a time.

## Providing a manifest definition on the command line

To provide the [manifest definition](#manifest-definition-file) in a command line argument instead of a file, use the `--config` / `-c` option.

For example, the following command adds a custom assertion called "org.contentauth.test".

```shell
c2pa-attacks sample/image.json -c '{"assertions": [{"label": "org.contentauth.test", "data": {"my_key": "C2PA_ATTACK"}}]}' -t regex -a attacks/xss.attack
```

## Adding a manifest to an asset file

To add C2PA manifest data to a file, provide the path to the asset file to be signed and use the `--manifest` / `-m` option with a manifest JSON file as the option argument. Then, use the `--output` / `-o` option to specify the desired location and name suffix for the output files. The output option is required to generate manipulated files. All of the manipulated files will be put in the same folder as the image specified in the output flag. For example, assume the following command line:

```shell
c2pa-attacks sample/image.jpg -m sample/test.json -o sample_out/signed_image.jpg -t title -a attacks/xss.attack
```

In the example above, all of the generated files will be placed in the `sample_out` directory. If the `sample_out` directory does not exist, then it will be created. The first generated file would be named, `sample_out/title_xss_0_signed_image.jpg`, as previously described. 

CAUTION: If the output file is the same as the source file, the tool will overwrite the source file. 

If you do not use the `--output` / `-o` option, then the tool will not generate any output.

### IMPORTANT NOTE

Since the C2PA Attack tool produces multiple output files per run, the filename specified in the output flag will be prefixed with the target type and the line number from the attack file that was injected. Therefore, the above example would produce the files: *title_0_signed_image.jpg*, *title_1_signed_image.jpg*, *title_2_signed_image.jpg*, etc.

### Specifying a parent file

A parent file represents the state of the image before the current edits were made. 

Specify a parent file as the argument to the `--parent` / `-p` option; for example:

```shell
c2pa-attacks sample/image.jpg -m sample/test.json -p sample/c.jpg -o sample_out/signed_image.jpg -t title -a attacks/xss.attack
```

You can also specify a parent file in the manifest definition.

## Detailed manifest report

To display a detailed report describing the internal C2PA format of manifests contained in the asset, use the `-d` option. This only works when `-v` is also specified.  The tool displays the detailed report to standard output (stdout). 

### Forced overwrite

The tool will return an error if the output file already exists. Use the `--force` / `-f` option to force overwriting the output file. For example:

```shell
c2pa-attacks sample/image.jpg -m sample/test.json -f -o sample_out/signed_image.jpg
```


