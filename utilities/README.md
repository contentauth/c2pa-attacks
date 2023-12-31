## Utilities

This directory contains various utilities that can make the creation and management of attack files more convenient.

### generate_sample_out.sh
This script is designed to generate all possible combinations of the malicious attacks based on the sample files. The script must be run from the root directory of the project. It requires one argument which is the path to the c2pa-attacks binary to use for building the sample malicious files. The following command demonstrates running the script from the root directory with all of the defaults:

`./utilities/generate_sample_out.sh {location_of_the_c2pa-attacks_binary}`

There are some combinations that the script does not build. For instance, the `C.jpg` image and the `malicious_certificate.json` manifest are not used with the default flags. The following additional flags may be specified to modify the default settings:

| Flag | Description |
|-----|-----|
| `-d` | Enable the output of debugging information. |
| `-m` | The JSON manifest file location for non-regex substitions. This is used in the `standard` and `all` target modes. Default: `./sample/test.json` |
| `-n` | The output file base name prior to being prefixed with attack details. Default: `signed_image.jpg` |
| `-o` | The output directory for the newly created files. Default: `./sample_out/` |
| `-r` | The location of the JSON manifest file for `regex` subsitutions. Default: `./sample/author_name_regex.json` | 
| `-s` | The location of the source image file that will be altered. Default: `./sample/image.jpg` |
| `-t` | The targeted manifest type. Allowed values are `all`, `standard`, and `regex`. Default: `all` |

The `-t` flag allows you to either skip the usage of a regex manifest file or to only use a regex manifest file. This option is provided because regex substitions require a dedicated manifest file with a `C2PA_ATTACK` field specified where you want the injections to occur. The `standard` mode will work with any standard JSON manifest and inject into specification defined fields such as `author` and `title`. The default regex example file makes substitutions in the `author` field. The default setting of `all` will build both the `standard` variants using `test.json` and the `regex` variant using the `author_name_regex.json` manifest from the sample directory. However, you can modify this behavior using the command line flags. For instance, if you wanted to limit the tool to only create malicious files using your own custom regex manifest file, then you could specify the following command:

`./utilities/generate_sample_out.sh -t regex -r {location_of_your_regex_manifest} {location_of_the_c2pa-attacks_binary}`

Anonther example customization of the command line might be to use the malicious certificate manifest definition which will sign the files with the default malicious certificate. Assuming that a locally installed c2pa-attacks binary will be used, the commmand would be as follows:

`./utilities/generate_sample_out.sh -m ./sample/malicious_certificate.json ~/.cargo/bin/c2pa-attacks`
