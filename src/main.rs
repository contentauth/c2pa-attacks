// Copyright 2023 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.
// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

#![doc = include_str!("../README.md")]
/// Tool to display and create C2PA security testing content
///
/// Example command: ./target/x86_64-apple-darwin/release/c2pa-attacks \
/// ./sample/C.jpg  -m ./sample/test.json -o ./sample_out/C_mod.jpg \
/// -f -t author -a ./attacks/xss.txt
use std::{
    collections::HashMap,
    fs::{create_dir_all, File},
    io::{self, BufRead},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};
use c2pa::{
    assertions::{labels, CreativeWork, SchemaDotOrgPerson},
    Error, Manifest, ManifestStore, ManifestStoreReport,
};
use clap::Parser;
use regex::Regex;
use serde_json::{Map, Value};

mod signer;
use serde::Deserialize;
use signer::SignConfig;

#[derive(Debug, Default, Deserialize)]
// Add fields that are not part of the standard Manifest
struct ManifestDef {
    #[serde(flatten)]
    manifest: Manifest,
    // Not used in this code
    //#[serde()]
    // allows adding ingredients with file paths
    //ingredient_paths: Option<Vec<PathBuf>>,
}

// define the command line options
#[derive(Parser, Debug)]
#[command(
    name = "c2pa-attacks",
    about = "A tool that can create C2PA manifests for the purposes of security testing."
)]
struct CliArgs {
    /// The path for the original asset image
    #[arg(required = true)]
    path: PathBuf,

    /// Path to manifest definition JSON file
    #[arg(short = 'm', required = true)]
    manifest_file: Option<PathBuf>,

    /// Path to the output folder and base file name for the output
    #[arg(short = 'o', required = true)]
    output: Option<PathBuf>,

    /// The target field to replace or indicating the use of regex mode
    #[arg(
        short = 't',
        required = true,
        value_parser = clap::builder::PossibleValuesParser::new([
        "author",
        "title",
        "format",
        "label",
        "vendor",
        "person_identifier",
        "instance_id",
        "claim_generator",
        "regex"])
    )]
    target: Option<String>,

    /// The file containing the attack strings to use
    #[arg(short = 'a', required = true)]
    attack_file: String,

    /// Path to a parent file
    #[arg(short = 'p')]
    parent: Option<PathBuf>,

    /// Manifest definition passed as a JSON string
    #[arg(short = 'c')]
    config: Option<String>,

    /// Display detailed C2PA-formatted manifest data
    #[arg(short = 'd')]
    detailed: bool,

    /// Force overwriting of any pre-existing output files
    #[arg(short = 'f')]
    force: bool,

    /// Display verbose output
    #[arg(short = 'v')]
    verbose: bool,
}

/**
 * prints the requested kind of report or exits with an error
 */
fn report_from_path<P: AsRef<Path>>(path: &P, is_detailed: bool) -> Result<String> {
    let report = match is_detailed {
        true => ManifestStoreReport::from_file(path).map(|r| r.to_string()),
        false => ManifestStore::from_file(path).map(|r| r.to_string()),
    };
    // Map some errors to strings we expect
    report.map_err(|e| match e {
        Error::JumbfNotFound => anyhow!("No claim found"),
        Error::FileNotFound(name) => anyhow!("File not found: {}", name),
        Error::UnsupportedType => anyhow!("Unsupported file type"),
        Error::PrereleaseError => anyhow!("Prerelease claim found"),
        _ => e.into(),
    })
}

// The file containing the injection attacks needs to be read line-by-line
// This will return an Iterator to the Reader of the lines of the file.
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

// Malicious strings may have double quotes or backslashes that need to be escaped for the JSON manifest. This function will take the injection string and escape any backslashes or double quotes that might be mistakenly interpreted by JSON.
//
// A trailing backslash needs to be escaped because it may be the last character in the string causing the double quote terminating the string to be escaped. Double quotes need to be escaped because they will conflict with existing JSON double quotes.
//
// This returns the injection string with the appropriate characters escaped.
fn escape_malicious_string(mal_string: String) -> Result<String> {
    // First escape any ending backslashes
    // Only escape if the last backslash isn't already escaped.
    let escaped_string: String = if mal_string.ends_with('\\') && !mal_string.ends_with("\\\\") {
        let escape_backslash = Regex::new(r#"(?P<a>\\)"#).unwrap();
        let temp = escape_backslash
            .replace_all(mal_string.as_str(), "\\\\")
            .to_string();

        // Next, add backslashes for any existing double quotes
        let escape_d_quote = Regex::new(r#"(?P<a>")"#).unwrap();
        escape_d_quote
            .replace_all(temp.as_str(), r#"\""#)
            .to_string()
    } else {
        // Add backslashes for any existing double quotes
        let escape_d_quote = Regex::new(r#"(?P<a>")"#).unwrap();
        escape_d_quote
            .replace_all(mal_string.as_str(), r#"\""#)
            .to_string()
    };
    Ok(escaped_string)
}

// Remove any pre-existing assertion of the same type as the malicious assertion.
fn remove_existing_assertion(
    orig_json: String,
    field_type: String,
    verbose: bool,
) -> HashMap<String, Value> {
    let map: Map<String, Value> = serde_json::from_str(&orig_json).expect("failed to read file");

    let blank_json: &str = "{}";
    let mut new_json: HashMap<String, Value> =
        serde_json::from_str(blank_json).expect("Couldn't create blank map");

    for entry in map.keys() {
        if entry == "assertions" {
            let mut vec = Vec::new();
            for assertion in map[entry].as_array().unwrap() {
                if assertion["label"].eq(labels::CREATIVE_WORK) {
                    let data = assertion["data"].as_object().unwrap();

                    // Only push the value if it doesn't contain authorship information
                    if !(data.contains_key("author") && field_type.eq("author")
                        || (data.contains_key("author") && field_type.eq("person_identifier"))
                        || (data.contains_key("creator") && field_type.eq("person_identifier")))
                    {
                        vec.push(assertion.clone());
                    } else if verbose {
                        println!("Dropping Creative Work from original source");
                    }
                } else {
                    vec.push(assertion.clone());
                }
            }
            new_json.insert("assertions".to_string(), Value::Array(vec));
        } else {
            new_json.insert(entry.to_string(), map[entry].clone());
        }
    }

    new_json
}

// For attack types of author or person_identifier, we will create a new malicious
// Creative Work assertion with the appropriate malicous fields.
fn malicious_creative_work(
    field_type: String,
    mal_string: &mut String,
) -> Result<Option<CreativeWork>> {
    let mut new_creative_work: Option<CreativeWork> = None;

    if field_type.eq("author") {
        let author = SchemaDotOrgPerson::new().set_name(mal_string.to_owned())?;
        new_creative_work = Some(CreativeWork::new().add_author(author).expect("add_author"));
    } else if field_type.eq("person_identifier") {
        let cw_person = SchemaDotOrgPerson::new()
            .set_name("Malicious User".to_owned())
            .unwrap()
            .set_identifier(mal_string.to_owned())
            .unwrap()
            .insert("@id".to_owned(), [mal_string.to_owned()].to_vec())
            .unwrap();
        new_creative_work = Some(
            CreativeWork::new()
                .add_author(cw_person.clone())
                .expect("add_author")
                // example of adding a different kind of person field
                .insert("creator".to_owned(), cw_person)
                .expect("insert"),
        );
    }

    Ok(new_creative_work)
}

// This function will create the malicious output files.
//
// The output files are of the format:
//
// {targeted_field}_{line_no_from_injection_file}_{original_name_of_input_file}
//
// The line numbers from the injection file start at zero.
fn output_file(
    args: &mut CliArgs,
    manifest: &mut Manifest,
    sign_config: &mut SignConfig,
    field_type: String,
    mal_string: &mut String,
    loop_index: &mut i64,
    testing_mode: bool,
) -> Result<()> {
    let mut new_creative_work: Option<CreativeWork> = None;

    if field_type.eq("author") || field_type.eq("person_identifier") {
        new_creative_work = malicious_creative_work(field_type.clone(), mal_string).unwrap();
    }

    if let Some(new_assertion) = new_creative_work {
        manifest.add_assertion(&new_assertion)?;
    }

    if field_type.eq("title") {
        manifest.set_title(mal_string.to_owned());
    }

    if field_type.eq("claim_generator") {
        manifest.set_claim_generator(mal_string.to_owned());
    }

    if field_type.eq("label") {
        manifest.set_label(mal_string.to_owned());
    }

    if field_type.eq("format") {
        manifest.set_format(mal_string.to_owned());
    }

    if field_type.eq("vendor") {
        manifest.set_vendor(mal_string.to_owned());
    }

    if field_type.eq("instance_id") {
        manifest.set_instance_id(mal_string.to_owned());
    }

    if let Some(mut output) = args.output.clone() {
        if output.extension() != args.path.extension() {
            bail!("output type must match source type");
        }
        if output.exists() && !args.force {
            bail!("Output already exists, use -f/force to force write");
        }

        if output.file_name().is_none() {
            bail!("Missing filename on output");
        }
        if output.extension().is_none() {
            bail!("Missing extension output");
        }

        let temp_path = args.attack_file.clone();
        let attack_file_path = Path::new(&temp_path);
        let attack_file_name = attack_file_path.file_stem().unwrap();

        let filename = output.file_name();
        let orig_file = filename.unwrap().to_str();
        let mut new_filename = field_type;
        new_filename.push('_');
        new_filename.push_str(attack_file_name.to_str().unwrap());
        new_filename.push('_');
        new_filename.push_str(loop_index.to_string().as_str());
        new_filename.push('_');
        new_filename.push_str(orig_file.unwrap());
        output.pop();
        output.push(new_filename);

        if args.verbose {
            println!("File to be created: {:?}", output.to_str());
        }

        let signer = sign_config.signer()?;

        if testing_mode {
            return Ok(());
        }

        // create any needed folders for the output path (embed should do this)
        let mut output_dir = PathBuf::from(&output);
        output_dir.pop();
        create_dir_all(&output_dir)?;

        manifest
            .embed(args.path.clone(), output.clone(), signer.as_ref())
            .context("embedding manifest")?;

        if args.verbose {
            // generate a report on the output file
            println!(
                "Result: {}",
                report_from_path(&output, args.detailed).unwrap()
            );
        }
    }
    Ok(())
}

// Create the malicious manifest containing the chosen attack string.
fn create_manifest_def(
    json: String,
    field_type: String,
    mal_string: String,
    verbose: bool,
) -> Result<ManifestDef> {
    // Define the string that the regex mode will use to find and use to subsitute injection strings
    let re = Regex::new(r"(?P<a>C2PA_ATTACK)").unwrap();

    if re.is_match(json.as_str()) && field_type.eq("regex") {
        let escaped_string: String = escape_malicious_string(mal_string).unwrap();

        let after = re.replace_all(json.as_str(), escaped_string);

        Ok(serde_json::from_str(&after)?)
    } else {
        let new_map = remove_existing_assertion(json, field_type, verbose);
        let new_string = serde_json::to_string(&new_map).unwrap();
        Ok(serde_json::from_slice(new_string.as_bytes())?)
    }
}

// This function will create the individual malicious files (except when in test mode)
// It is called within the loop in main which is reading each line of the malicious inputs
fn create_file(
    field_type: String,
    loop_index: &mut i64,
    mal_string: String,
    args: &mut CliArgs,
    testing_mode: bool,
) -> Result<()> {
    let mut escaped_string = mal_string.clone();

    let config = args.config.clone();

    // if we have a manifest config, process it
    if args.manifest_file.is_some() || config.is_some() {
        // read the json from file or config, and get base path if from file
        let (json, base_path) = match args.manifest_file.as_deref() {
            Some(manifest_path) => {
                let base_path = manifest_path.parent();
                (std::fs::read_to_string(manifest_path)?, base_path)
            }
            None => (config.unwrap_or_default(), None),
        };

        // read the signing information from the manifest definition
        let mut sign_config = SignConfig::from_json(&json)?;

        let manifest_def: ManifestDef =
            match create_manifest_def(json, field_type.clone(), mal_string.clone(), args.verbose) {
                Ok(_v) => {
                    // println!("Success");
                    _v
                }
                Err(e) => {
                    println!(
                        "Error: Skipping creating malicious file with {mal_string} due to: {e:?}"
                    );
                    return Err(e);
                }
            };

        let mut manifest: Manifest = manifest_def.manifest;

        // add claim_tool generator so we know this was created using this tool
        let tool_generator = format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        if manifest.claim_generator.starts_with("c2pa/") {
            manifest.claim_generator = tool_generator // just replace the default generator
        } else {
            manifest.claim_generator = format!("{} {}", manifest.claim_generator, tool_generator);
        }

        if let Some(base) = base_path {
            manifest.resources_mut().set_base_path(base);
            sign_config.set_base_path(base);
        }

        // If we successfully have a manifest config, then proceed with creating attack files.
        if let Some(parent_path) = args.parent.clone() {
            manifest.set_parent(c2pa::Ingredient::from_file(parent_path)?)?;
        }

        // If the source file has a manifest store, and no parent is specified, then treat the source as a parent.
        // note: This could be treated as an update manifest eventually since the image is the same
        let source_ingredient = c2pa::Ingredient::from_file(&args.path)?;
        if source_ingredient.manifest_data().is_some() && manifest.parent().is_none() {
            manifest
                .set_parent(source_ingredient)
                .expect("Set_parent failed to return");
        }

        let result = output_file(
            args,
            &mut manifest,
            &mut sign_config,
            field_type,
            &mut escaped_string,
            loop_index,
            testing_mode,
        );
        match result {
            Ok(_v) => {
                *loop_index += 1;
            }
            Err(e) => println!("Failed to process file: {e:?}"),
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let mut args = CliArgs::parse();

    // set RUST_LOG=debug to get detailed debug logging
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "error");
    }
    env_logger::init();

    // Verify command line flag for the target is one that is supported by this tool
    let field_type: String = if let Some(target) = args.target.clone() {
        let target_str = target.to_owned();
        if target_str.ne("author")
            && target_str.ne("title")
            && target_str.ne("claim_generator")
            && target_str.ne("regex")
            && target_str.ne("person_identifier")
            && target_str.ne("instance_id")
            && target_str.ne("label")
            && target_str.ne("format")
            && target_str.ne("vendor")
        {
            bail!("Unrecognized field type. Allowed values: author, title, label, format, vendor, instance_id, claim_generator, person_identifier, or regex");
        }
        target
    } else {
        bail!("Field type not provided. Please add the '-t' flag.");
    };

    // Set to track the current line in the injection file.
    let mut loop_index = 0;

    // If we can successfully read the injection file path
    if let Ok(lines) = read_lines(args.attack_file.clone()) {
        // Consumes the iterator, returns an (Optional) String
        for mal_string in lines.flatten() {
            if create_file(
                field_type.clone(),
                &mut loop_index,
                mal_string,
                &mut args,
                false,
            )
            .is_err()
            {
                println!("Failed to create file: {}", loop_index);
            }
        }
    } else {
        bail!("ERROR: Could not find the attack injection file!");
    }

    Ok(())
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    use std::path::PathBuf;

    use crate::CliArgs;

    #[test]
    // Perform a unit test of injecting an XSS string in the title.
    // This will not create any files.
    fn test_xss_title() {
        let path: PathBuf = [r"sample", "image.jpg"].iter().collect();
        let manifest_temp: Result<PathBuf, ()> = Ok([r"sample", "test.json"].iter().collect());
        let manifest_file: Option<PathBuf> = manifest_temp.ok();
        let output_temp: Result<PathBuf, ()> =
            Ok([r"sample_out", "signed_image.jpg"].iter().collect());
        let output: Option<PathBuf> = output_temp.ok();
        let target_temp: Result<String, ()> = Ok(String::from("title"));
        let target: Option<String> = target_temp.ok();
        let config: Option<String> = None;
        let attack_file: String = String::from("attacks/xss.attack");
        let detailed: bool = false;
        let force: bool = false;
        let verbose: bool = false;

        let parent: Option<PathBuf> = None;
        let field_type: String = String::from("title");

        let mut test_cli: CliArgs = CliArgs {
            path,
            manifest_file,
            output,
            target,
            attack_file,
            parent,
            config,
            detailed,
            force,
            verbose,
        };

        let mut loop_index: i64 = 0;

        assert!(create_file(
            field_type,
            &mut loop_index,
            String::from("<script>alert('hi');</script>"),
            &mut test_cli,
            true
        )
        .is_ok())
    }

    #[test]
    // Perform a unit test of injecting an XSS string in regex mode.
    // This will not create any files.
    fn test_xss_regex_author() {
        let path: PathBuf = [r"sample", "image.jpg"].iter().collect();
        let manifest_temp: Result<PathBuf, ()> =
            Ok([r"sample", "author_name_regex.json"].iter().collect());
        let manifest_file: Option<PathBuf> = manifest_temp.ok();
        let output_temp: Result<PathBuf, ()> =
            Ok([r"sample_out", "signed_image.jpg"].iter().collect());
        let output: Option<PathBuf> = output_temp.ok();
        let target_temp: Result<String, ()> = Ok(String::from("regex"));
        let target: Option<String> = target_temp.ok();
        let config: Option<String> = None;
        let attack_file: String = String::from("attacks/xss.attack");
        let detailed: bool = false;
        let force: bool = false;
        let verbose: bool = false;

        let parent: Option<PathBuf> = None;
        let field_type: String = String::from("regex");

        let mut test_cli: CliArgs = CliArgs {
            path,
            manifest_file,
            output,
            target,
            attack_file,
            parent,
            config,
            detailed,
            force,
            verbose,
        };

        let mut loop_index: i64 = 0;

        assert!(create_file(
            field_type,
            &mut loop_index,
            String::from("<script>alert('hi');</script>"),
            &mut test_cli,
            true
        )
        .is_ok())
    }
}
