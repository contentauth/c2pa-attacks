## Utilities

This directory contains various utilities that can make the creation and management of attack files more convenient.

### generate_sample_out.sh
This script is designed to generate all possible combinations of the malicious attacks based on the sample files. The script must be run from the root directory of the project. It requires one argument which is the path to the c2pa-attacks binary to use for building the sample malicious files. The following command demonstrates running the script from the root directory with all of the defaults:

`./utilities/generate_sample_out.sh {location_of_the_c2pa-attacks_binary}`

There are some combinations that the script does not build. For instance, the `C.jpg` image and the `malicious_certificate.json` manifest are not used with the default flags. The following additional flags may be specified to modify the default settings:

| Flag | Description |
|-----|-----|
| `-d` | Enable the output of debugging information. |
| `-m` | The JSON manifest file location for non-regex substitutions in `standard` and `all` modes. Default: `./sample/cawg_metadata.json` |
| `-n` | The output file base name prior to being prefixed with attack details. Default: `signed_image.jpg` |
| `-o` | The output directory for the newly created files. Default: `./sample_out/` |
| `-r` | The JSON manifest file for `regex` substitutions. Default: `./sample/cawg_author_regex.json` |
| `-s` | The location of the source image file that will be altered. Default: `./sample/image.jpg` |
| `-t` | The targeted manifest type. Allowed values are `all`, `standard`, and `regex`. Default: `all` |

The default `all` mode tests claim fields such as title, CAWG metadata, retained legacy CreativeWork targets, and template substitutions. CAWG support adds to the tool's broader C2PA manifest testing; it does not replace other targets. The `regex` mode uses a JSON template with `C2PA_ATTACK` at the desired string location. Change the template to test other assertion fields or schemas without adding flags. Use `-r ./sample/cawg_person_identifier_regex.json` for identifiers or a custom template for Dublin Core metadata.

The `standard` and default `all` modes include `cawg_author`, `cawg_person_identifier`, claim-field targets, and the retained legacy `author`/`person_identifier` targets. The latter deliberately create CreativeWork assertions and print warnings; use a claim-v1 definition such as `sample/test.json` for legacy-specific testing. `all` also includes template batches. `-m` selects the definition used for non-template batches.

For a custom template:

`./utilities/generate_sample_out.sh -t regex -r {location_of_your_regex_manifest} {location_of_the_c2pa-attacks_binary}`

The binary argument must be an executable file path (for example `./target/debug/c2pa-attacks` or `~/.cargo/bin/c2pa-attacks`). Arguments are passed literally, so file paths with spaces are supported; the script does not evaluate a shell command string. A failed batch is reported and other batches are still attempted, then the script exits unsuccessfully. Some attack strings intentionally violate SDK validation rules; those failures are not silently treated as successes.

Anonther example customization of the command line might be to use the malicious certificate manifest definition which will sign the files with the default malicious certificate. Assuming that a locally installed c2pa-attacks binary will be used, the commmand would be as follows:

`./utilities/generate_sample_out.sh -t standard -m ./sample/malicious_certificate.json ~/.cargo/bin/c2pa-attacks`
