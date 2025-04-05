#!/bin/bash

# Copyright 2025 Adobe. All rights reserved.
# This file is licensed to you under the Apache License,
# Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
# or the MIT license (http://opensource.org/licenses/MIT),
# at your option.
# Unless required by applicable law or agreed to in writing,
# this software is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
# implied. See the LICENSE-MIT and LICENSE-APACHE files for the
# specific language governing permissions and limitations under
# each license.

# This script is designed to build all supported attacks based on the sample files.
# It doesn't build variants using C.jpg or the malicious certificate by default.
# These can be built used by changing the defaults using the command line.
#
# It is expected that this tool will be run from the root directory of the project.
# ./scripts/generate_sample_out.sh {location_of_the_c2pa-attacks_binary_to_use}
#
# Not all combinations of malicious files can be built. This will result in a few known errors.
# These errors will either mention a CBOR error or they will say that a file is being skipped.
# These errors are expected and doesn't indicated a failure of the tool.
# The errors are only displayed when the tool is in debugging mode.

# Whether to output debugging information
debugging=false

# The list of target locations where substitutions will occur
# format and instance_id are not used in the current implementation and are temporarily removed
# "instance_id" "format"
target_fields=("title" "author" "person_identifier" "claim_generator" "vendor" "label" "regex")

# The location of the attack file directory.
attack_dir="./attacks/"

# The list of attack files to use for this run.
# These are assumed to exist in the attack_dir directory.
attack_files=("rendering.attack" "special_characters.attack" "sql_injection.attack" "ten_thousand_characters.attack" "xss.attack")

# The source JSON manifest file for non-regex use cases.
# This uses the standard es256 certificate files from the sample directory
source_json="./sample/test.json"

# This manifest file is similar to test.json but it uses the malicious_certificate for signing.
# It is not intended for the regex mode of c2pa-attacks
malicious_cert_json="./sample/malicious_certificate.json"

# Setting the default manifest that will be used.
# This can be overridden by the command line.
manifest_file="${source_json}"

# The base JSON manifest file for use with the regex functionality.
# This file has the string "C2PA_ATTACK" embedded within it.
# The "C2PA_ATTACK" string will be replaced with the malicious string. 
regex_test_file="./sample/author_name_regex.json"

# The default output directory where newly created files will be placed.
sample_out_dir="./sample_out/"

# The default base name of the newly created file.
# This name will be prefixed with information about the modifications.
output_name="signed_image.jpg"

# The default source image that will have content credentials added to it.
source_image="./sample/image.jpg"

# targets
build_target="all"

# Display usage information when an unexpected or malformed flag is provided.
usage() {
    echo "USAGE: $(basename $0) [-d] [-m manifest_file] [-n output_file_name] [-o output_file_directory] [-s source_image]  binary_location" >&2
    echo "-d: Print debugging statements"
    echo "-m: The location of a manifiest file for non-regex substitutions. (default: ${source_name})"
    echo "-n: The ending to use for output file names. (default: ${output_name})"
    echo "-o: The output file directory. (default: ${sample_out_dir})"
    echo "-r: The location of the manifest file for regex substitutions. (default: ${regex_test_file})"
    echo "-s: The source image file that will be altered. (default: ${source_image})"
    echo "-t: The type of manifest files to use (all, standard, or regex). (default: ${build_target})"
}

# Retrieve any optional command line parameters
while getopts 'dm:n:o:r:s:t:' OPTION; do
  case "$OPTION" in
    d)
        debugging=true
    ;;
    m)
        manifest_file="${OPTARG}"
        if ! test -f "$manifest_file"; then
            echo "ERROR: Invalid manifest file location"
            exit 1
        fi
    ;;
    n)
        output_name="${OPTARG}"
    ;;
    o)
        sample_out_dir=="${OPTARG}"
    ;;
    r)
        regex_test_file="${OPTARG}"
        if ! test -f "$regex_test_file"; then
            echo "ERROR: Invalid regex manifest file location"
            exit 1
        fi
    ;;
    s)
        source_image="${OPTARG}"
        if ! test -f "$source_image"; then
            echo "ERROR: Invalid source image file location"
            exit 1
        fi
    ;;
    t)
        build_target="${OPTARG}"
        if [ "${build_target}" != "all" ] &&  [ "${build_target}" != "standard" ] && [ "${build_target}" != "regex" ] ; then
            echo "ERROR: Invalid target field selection. The value must be all, standard, or regex"
            exit 1
        fi
    ;;
    ?)
      usage
      exit 0
    ;;
  esac
done

# Reset $1 to the location of c2pa-attacks binary if necessary
if [ $OPTIND -gt 0 ] ; then
    shift "$(($OPTIND - 1))"
fi

# Check for the location of the c2pa-attacks binary in $1
if [ -z "$1" ] ; then
    echo "ERROR: Please supply the location of the c2pa-attacks binary to use for the builds"
    usage
    exit 1
fi

# Set the location of the c2pa-attacks binary.
binary_location="$1"

# Verify that the path to the c2pa-attacks binary is valid
if ! type "$binary_location" > /dev/null; then
    echo "ERROR: Unable to locate the provided location of the c2pa-attacks binary"
    echo "Please double check the path provided to ensure that it points to a valid location"
    exit 1
fi

# Display debugging information on which files will be created
if [ "$debugging" = true ] ; then
    if [ "${build_target}" = "regex" ]; then
        echo "DEBUG: Only building files based on the regex manifest"
    elif [ "${build_target}" = "standard" ]; then
        echo "DEBUG: Only building based on a standard manifest file. The regex manifest will be ignored."
    else
        echo "DEBUG: Building all combinations of files."
    fi
fi

# Start creating the malicious files in the output directory.

# For each of the listed attack files
for attack_file in "${attack_files[@]}"; do

    ## For each of the target substitution locations
    for target_field in "${target_fields[@]}"; do

        # Ignore regex substitutions if it is in standard-only mode
        if [ "${target_field}" = "regex" ] && [ "${build_target}" = "standard" ]; then
            continue
        fi

        # Ignore standard fields if it is regex-only mode
        if [ "${target_field}" != "regex" ] && [ "${build_target}" = "regex" ]; then
            continue
        fi

        # Build the command line with all of the appropriate values
        command_line="${binary_location}  ${source_image}"

        if [ "${target_field}" = "regex" ]; then
            command_line="${command_line} -m ${regex_test_file}"
        else
            command_line="${command_line} -m ${source_json}"
        fi

        # command_line="${command_line} -v"
        command_line="${command_line} -o ${sample_out_dir}${output_name}"
        command_line="${command_line} -t ${target_field}"
        command_line="${command_line} -a ${attack_dir}${attack_file}"
        command_line="${command_line} -f"

        # Show the complete command line when debugging
        if [ "$debugging" = true ] ; then
            echo "DEBUG: ${command_line}"
        fi

        # Execute the command line and capture any errors
        output=$(eval $command_line)

        # Output errors from the command line
        # This is only printed in debugging mode because some errors are expected in normal operation.
        if [ -n "$output" ] && [ "$debugging" = true ] ; then
            echo "${output}"
        fi
    done

done